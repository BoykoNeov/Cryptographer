/**
 * Salsa20/20 (Bernstein, 2005) — the app's SECOND stream cipher, and ChaCha20's
 * direct ancestor.
 *
 * Same designer, same ARX family, same 4×4 word state, same keystream-⊕-message
 * structure. Like ChaCha20 it has no `BlockCipherCore` and needs none: it is a
 * keystream generator that already contains its own counter, so it borrows
 * CTR's *shape* (an `iterate`, a counter on the cross-iteration carry, a
 * `truncate-to-reference@1` for the ragged tail, a final `xor@1`) without
 * touching any of the mode machinery.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * WHAT THIS CIPHER BUYS THAT CHACHA20 DID NOT.
 *
 * Two things, and both are structural rather than cryptographic:
 *
 * 1. It is the first evidence that `"stream"` was correctly modelled as a sixth
 *    `CipherMode` rather than a per-cipher predicate. Salsa20 costs exactly one
 *    row in `SUPPORTED_CIPHER_MODES_BY_CIPHER` and ZERO new arms on
 *    `isStreamCipher` / `isStreamCipherMode` / `cipherModeUsesIv` /
 *    `defaultCipherModeFor` — because every one of those already derives from
 *    that row. Had the abstraction been wrong, this cipher is where it would
 *    have shown.
 *
 * 2. **The state is diagonal, not four contiguous regions.** This is the
 *    pedagogical payload. ChaCha20 assembles its state from four runs —
 *    constants, key, counter, nonce — so its `concat@1` has `inputCount: 4`.
 *    Salsa20 scatters the same material along the matrix's diagonal:
 *
 *      c0 ‖ k0..k3 ‖ c1 ‖ nonce ‖ counter ‖ c2 ‖ k4..k7 ‖ c3
 *
 *    Eight contiguous runs, so `inputCount: 8`. ChaCha's regrouping of the
 *    state into neat regions was one of Bernstein's own later simplifications;
 *    seeing the two assemblies side by side is the clearest way to notice it.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * ENDIANNESS — read this before editing anything below.
 *
 * Identical convention to ChaCha20, which is identical to Twofish's: the cipher
 * is natively LITTLE-endian, the app's ARX primitives (`add-mod-32@1`,
 * `rotate-bits-left@1`) are BIG-endian, so **words travel the ports big-endian
 * and every LE↔BE crossing is a visible `permute@1` at an endpoint.** A
 * rotation is defined on the 32-bit *value*, so `<<< 7` is `<<< 7` under either
 * serialization; this is a serialization convention, not a change to the cipher.
 *
 * The crossings:
 *
 *   1. `key-be`       — the 32-byte key,   8 word reversals
 *   2. `nonce-be`     — the 8-byte nonce,  2 word reversals
 *   3. `counter-init` — the counter, ONE 8-byte reversal (see below)
 *   4. `keystream`    — the 64-byte output, 16 word reversals
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE 64-BIT COUNTER is the one genuinely new wrinkle versus ChaCha20, whose
 * counter is a single 32-bit word. Salsa20's occupies state words 8 AND 9 as
 * one 64-bit little-endian integer, which means it is touched in three places
 * and they do not agree on shape:
 *
 *   - `counter-init` (outside the loop) reverses ALL EIGHT bytes at once — not
 *     two 4-byte reversals — producing a big-endian 64-bit number.
 *   - `increment-counter@1` reads that carry RAW. The step is big-endian and
 *     derives its width from the wired input, so an 8-byte input is incremented
 *     as one 64-bit number, carrying correctly from word 8 into word 9.
 *   - `counter-words` (inside the body) permutes `[4,5,6,7,0,1,2,3]` — swapping
 *     the two halves — because the state wants two big-endian *words*, low word
 *     first. The increment still reads the raw carry, not this.
 *
 * Getting any one of the three wrong produces plausible keystream that simply
 * will not interoperate. The KAT is the guard; see `tests/salsa20-kat.test.ts`.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * ENCRYPT AND DECRYPT ARE THE SAME SPEC — the message meets only an XOR, and
 * XOR is its own inverse. `direction` affects the spec id, name and prose ONLY.
 *
 * The testing consequence, inherited from OFB and ChaCha20: **round-tripping
 * this cipher proves nothing.** One spec used both ways round-trips by
 * construction even if the quarter round is entirely wrong. There is also no
 * `node:crypto` oracle for Salsa20, so verification rests on pinned external
 * vectors rather than a live reference — see the test file's header.
 */

import {
  type CipherSpec,
  INPUT_SOURCE_ID,
  INPUT_SOURCE_PORT,
  type PortBinding,
  type StepDocumentation,
  type StepNode,
} from "../core/types";
import { port } from "./block-cipher-core";

export type SalsaDirection = "encrypt" | "decrypt";

// ─── Constants ────────────────────────────────────────────────────────────

/** The cipher's block width: 64 bytes of keystream per counter value. */
export const SALSA20_BLOCK_BYTES = 64;
/** This build ships the 256-bit key variant only (`"expand 32-byte k"`). */
export const SALSA20_KEY_BYTES = 32;
/** The 16-byte `aux["iv"]` blob: an 8-byte LE counter then an 8-byte nonce. */
export const SALSA20_IV_BYTES = 16;
/** Salsa20's nonce is 8 bytes — two state words. ChaCha20's is 12. */
export const SALSA20_NONCE_BYTES = 8;
/** The counter is 64 bits wide, spanning two state words. */
export const SALSA20_COUNTER_BYTES = 8;

/**
 * The four constant words at state positions 0, 5, 10 and 15 — the matrix
 * diagonal — big-endian on the wire.
 *
 * Bernstein gives them as the little-endian reading of the ASCII string
 * `"expand 32-byte k"`, four bytes at a time:
 * `0x61707865, 0x3320646e, 0x79622d32, 0x6b206574`.
 *
 * Because words travel big-endian here, each entry below is that word's
 * big-endian encoding — which is the ASCII group REVERSED. Read as text the
 * array spells `"apxe" "3 dn" "yb-2" "k et"`, and that is expected: reversing
 * each group again recovers `"expa" "nd 3" "2-by" "te k"`.
 *
 * These are a nothing-up-my-sleeve number: a fixed, public, obviously arbitrary
 * value that could not have been chosen to hide a weakness. They also pin a
 * quarter of the state — and, in Salsa20's diagonal layout, specifically the
 * matrix's main diagonal — to something an attacker cannot influence.
 */
export const SALSA20_CONSTANT_WORDS: readonly (readonly number[])[] = [
  [0x61, 0x70, 0x78, 0x65], // 0x61707865, state word 0
  [0x33, 0x20, 0x64, 0x6e], // 0x3320646e, state word 5
  [0x79, 0x62, 0x2d, 0x32], // 0x79622d32, state word 10
  [0x6b, 0x20, 0x65, 0x74], // 0x6b206574, state word 15
];

/**
 * Bernstein's `columnround` then `rowround` — one double round. Ten of them.
 *
 * **The order within each tuple is load-bearing and must not be normalized.**
 * Each quarter round starts on the diagonal element of the column (or row) it
 * mixes, then walks it cyclically: the column containing word 5 is visited as
 * `(5, 9, 13, 1)`, not `(1, 5, 9, 13)`. Sorting these would compile, run, and
 * produce a completely different cipher.
 *
 * Alternating column and row mixing is what spreads a change in any one word to
 * every other: after a column round a difference has reached its whole column,
 * and the row round then carries it into every column.
 */
const QUARTER_ROUND_INDICES: readonly (readonly [number, number, number, number])[] = [
  // Column round — each quarter round mixes one column, starting on its diagonal.
  [0, 4, 8, 12],
  [5, 9, 13, 1],
  [10, 14, 2, 6],
  [15, 3, 7, 11],
  // Row round — each mixes one row, again starting on the diagonal.
  [0, 1, 2, 3],
  [5, 6, 7, 4],
  [10, 11, 8, 9],
  [15, 12, 13, 14],
];

const DOUBLE_ROUNDS = 10;

// Node ids referenced from more than one place.
const ITERATE_ID = "salsa-blocks";
const STATE_INIT_ID = "state-init";
const FINAL_ADD_ID = "final-add";
const KEYSTREAM_ID = "keystream";
const TRIM_ID = "salsa-trim";
const XOR_ID = "salsa-xor";
const INCREMENT_ID = "salsa-increment";
const COUNTER_INIT_ID = "counter-init";
const COUNTER_WORDS_ID = "counter-words";

// ─── Helpers ──────────────────────────────────────────────────────────────

/**
 * `permute@1` indices that reverse the bytes of every 32-bit word in a
 * `byteLength`-byte buffer — the LE↔BE crossing, and its own inverse.
 */
const wordReverseIndices = (byteLength: number): number[] => {
  const indices: number[] = [];
  for (let w = 0; w < byteLength / 4; w++) {
    indices.push(4 * w + 3, 4 * w + 2, 4 * w + 1, 4 * w);
  }
  return indices;
};

/** Sixteen equal 4-byte widths — splitting the state into its words. */
const STATE_WORD_WIDTHS: readonly number[] = Array.from({ length: 16 }, () => 4);

// ─── The quarter round ────────────────────────────────────────────────────

/**
 * Bernstein's `quarterround`. Given words (y0, y1, y2, y3):
 *
 * ```
 *   z1 = y1 ⊕ ((y0 + y3) <<<  7)
 *   z2 = y2 ⊕ ((z1 + y0) <<<  9)
 *   z3 = y3 ⊕ ((z2 + z1) <<< 13)
 *   z0 = y0 ⊕ ((z3 + z2) <<< 18)
 * ```
 *
 * Twelve operations from three kinds — Addition, Rotation, XOR: the ARX family.
 * No S-box, no lookup table, so every operation runs in constant time on
 * ordinary registers and the cipher has no cache-timing side channel of the
 * sort table-driven designs like AES must be implemented carefully to avoid.
 *
 * **The shape differs from ChaCha20's in a way worth seeing.** ChaCha
 * accumulates IN PLACE — `a += b; d ^= a; d <<<= 16` — so each of its twelve
 * ops mutates a named rail. Salsa computes into a FRESH rail: two sources are
 * added, the sum is rotated, and only then is the result XORed into a third
 * word. So of the three ops on each line, only the XOR writes back to the state.
 *
 * That is why this walk cannot reuse ChaCha's `add`/`xorInto`/`rotate` helpers,
 * which write their result back to the operand slot. The lines here read
 * already-updated slots (line 2 reads `z1`, not `y1`), so the order of the four
 * lines is as load-bearing as the index tuple.
 *
 * The rotation constants 7/9/13/18 are distinct, which is what lets the S3
 * shape analyzer recognize this walk by anchoring on the `<<< 18` that ends it.
 *
 * @param idPrefix unique per (double round, quarter round) — ids are trace keys
 * @param words    the live 16-word binding table, MUTATED in place at the target
 * @param quad     which four state words this quarter round mixes, in order
 */
const quarterRound = (
  idPrefix: string,
  words: PortBinding[],
  quad: readonly [number, number, number, number],
): StepNode[] => {
  const nodes: StepNode[] = [];

  /**
   * One written line: `words[target] ^= ROL(words[srcA] + words[srcB], bits)`.
   *
   * Three leaves — add, rotate, xor — of which only the last rebinds a state
   * word. The rotation constant doubles as the line's id, since 7/9/13/18 are
   * distinct within a quarter round.
   */
  const line = (target: number, srcA: number, srcB: number, bits: number): void => {
    const addId = `${idPrefix}.add-${bits}`;
    const rotId = `${idPrefix}.rot-${bits}`;
    const xorId = `${idPrefix}.xor-${bits}`;

    nodes.push(
      {
        kind: "step",
        id: addId,
        type: "add-mod-32@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: words[srcA] as PortBinding,
          operand1: words[srcB] as PortBinding,
        },
      },
      {
        kind: "step",
        id: rotId,
        type: "rotate-bits-left@1",
        params: { bits, wordBits: 32 },
        portInputs: { input: port(addId, "output") },
      },
      {
        kind: "step",
        id: xorId,
        type: "xor@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: words[target] as PortBinding,
          operand1: port(rotId, "output"),
        },
      },
    );

    // Only the XOR writes back — the add and the rotate live on a scratch rail.
    words[target] = port(xorId, "output");
  };

  const [i0, i1, i2, i3] = quad;

  line(i1, i0, i3, 7);
  line(i2, i1, i0, 9);
  line(i3, i2, i1, 13);
  line(i0, i3, i2, 18);

  return nodes;
};

// ─── Narration for the structural leaves ──────────────────────────────────

const narrConstants = (index: number): StepDocumentation => ({
  name: `Constant word ${index + 1} of 4`,
  summary: 'One of the four fixed words of "expand 32-byte k", sitting on the state diagonal.',
  detail: `## The constants — and why there are four of them, separately

\`\`\`
"expa"  "nd 3"  "2-by"  "te k"
\`\`\`

Together these four words spell the ASCII string \`expand 32-byte k\`. They are
the same for every key, every nonce and every message.

This is a **nothing-up-my-sleeve number**: a value so obviously arbitrary that
its designer could not plausibly have chosen it to hide a weakness. A constant
that looked random would invite the question "why *that* one?"; an English
sentence does not.

**Notice that this is a separate step from the other three.** In ChaCha20 the
four constants are one contiguous run at the top of the state, loaded in a
single step. Salsa20 places them at words 0, 5, 10 and 15 — the matrix's main
diagonal — so each is loaded on its own and concatenated into a different slot.
That scattering is the main structural difference between the two ciphers, and
regrouping it into neat regions was one of the simplifications ChaCha20 made.

They also do real work: a quarter of the state is fixed at a value the attacker
cannot influence, no matter what key, nonce or counter is supplied.`,
  references: ["Bernstein, *Salsa20 specification* (2005), §Salsa20 expansion"],
});

const narrKeyBe: StepDocumentation = {
  name: "Key → words",
  summary: "Reads the 32-byte key as eight 32-bit words, reversing each word's bytes.",
  detail: `## Reading the key as words

The key arrives as 32 bytes. Salsa20 works on 32-bit words, so those bytes are
read four at a time — and Salsa20 reads them **little-endian**, meaning the
first byte is the word's *lowest* 8 bits, not its highest.

This explorer moves words between steps big-endian, so each group of four bytes
is reversed here. Every byte of the key is still present and still in its own
word; only the order within each word changes.

That is what this step is: the boundary where the cipher's little-endian
convention meets the explorer's big-endian one. There are four such boundaries
in the whole cipher — this one, the nonce, the counter, and the keystream on
the way out — and nothing between them touches byte order again.

**These eight words do not stay together.** The next step cuts them in half:
words 0–3 go to state slots 1–4, words 4–7 to slots 11–14, with constants,
nonce and counter interleaved between them. Salsa20 splits its key across the
state; ChaCha20 keeps it in one run.`,
  references: ["Bernstein, *Salsa20 specification* (2005), §Salsa20 expansion"],
};

const narrKeyHalf = (isHigh: boolean): StepDocumentation => ({
  name: isHigh ? "Key words 4–7" : "Key words 0–3",
  summary: isHigh
    ? "The upper half of the key, bound for state words 11–14."
    : "The lower half of the key, bound for state words 1–4.",
  detail: `## Half a key

Salsa20 does not keep its key in one place. The 256-bit key is cut here into
two 128-bit halves that land on opposite sides of the state:

| key bytes | state words |
|---|---|
| 0–15  | 1–4   |
| 16–31 | 11–14 |

Between them sit a constant (word 5), the nonce (6–7), the counter (8–9) and
another constant (word 10).

There is no key schedule here at all — no expansion, no round keys, nothing
derived. The key is simply placed into the state and mixed by the rounds, which
is a large part of why Salsa20 and ChaCha20 are so fast in software and why they
have no key-setup cost to amortize over a message.`,
  references: ["Bernstein, *Salsa20 specification* (2005), §Salsa20 expansion"],
});

const narrNonceBe: StepDocumentation = {
  name: "Nonce → words",
  summary: "Reads the 8-byte nonce as two 32-bit words, reversing each word's bytes.",
  detail: `## The nonce

A **nonce** is a "number used once". It does not need to be secret and it does
not need to be unpredictable — but it must never repeat for a given key.

That single rule is doing an enormous amount of work. The keystream depends
only on the key, the nonce and the counter. Encrypt two different messages
under the same key AND the same nonce and they get the *same* keystream; XOR
the two ciphertexts together and the keystream cancels, leaving the two
plaintexts XORed with each other. That is recoverable, and it has broken real
systems.

**Salsa20's nonce is 8 bytes — 64 bits — where ChaCha20's is 12.** Salsa20
spends the other four bytes on a wider counter instead. Sixty-four bits is small
enough that picking nonces at random carries a real collision risk once you have
encrypted a great many messages under one key, which is why the safest schemes
simply count, and why the later XSalsa20 variant exists specifically to widen
the nonce to 192 bits.`,
  references: [
    "Bernstein, *Salsa20 specification* (2005)",
    "Bernstein, *Extending the Salsa20 nonce* (XSalsa20)",
  ],
};

const narrCounterInit: StepDocumentation = {
  name: "Initial counter",
  summary: "The first eight IV bytes, read as the little-endian 64-bit starting counter.",
  detail: `## Where the counter comes from

The IV field supplies 16 bytes:

\`\`\`
[ counter: 8 bytes, little-endian ][ nonce: 8 bytes ]
\`\`\`

This step takes the first eight and reads them as the starting block counter,
reversing the bytes for the same little-endian reason as the key and the nonce.

**All eight bytes are reversed together, as one 64-bit number** — not two
separate 4-byte word reversals. That matters because the counter really is a
single 64-bit integer that has to carry from its low half into its high half
when it passes 2³². Treating it as two independent words would produce a
counter that silently stopped counting correctly after four billion blocks.

The counter starts at **0** here, which is what standard Salsa20 implementations
do and what this explorer's test vectors assume. Any starting value works as
long as encryption and decryption agree — but a mismatched start is a classic
source of a bug that is very hard to see: the cipher produces perfectly
plausible ciphertext that simply will not decrypt anywhere else.`,
  references: ["Bernstein, *Salsa20 specification* (2005)"],
};

const narrCounterWords: StepDocumentation = {
  name: "Counter → two words",
  summary: "Splits the 64-bit counter into the state's two counter words, low word first.",
  detail: `## One number, two words

The counter is one 64-bit number. The state holds it as **two 32-bit words, low
half first**, at positions 8 and 9.

So this step swaps the two halves of the big-endian 64-bit value:

\`\`\`
[ high 32 bits ][ low 32 bits ]   →   [ low 32 bits ][ high 32 bits ]
\`\`\`

After the swap each half is still big-endian internally, which is what the state
and the arithmetic below expect.

Note that the counter is incremented *before* this step, on the raw 64-bit
value — that is the only place it is treated as a single number, and it is why
the carry from word 8 into word 9 works. Everything downstream sees two words.

This is the one place Salsa20 is genuinely more awkward than ChaCha20, whose
counter is a single word needing no such split. ChaCha20 traded half the counter
for a wider nonce.`,
  references: ["Bernstein, *Salsa20 specification* (2005)"],
};

const narrStateInit: StepDocumentation = {
  name: "Assemble the state",
  summary: "The eight runs — constants on the diagonal, key in two halves, nonce and counter.",
  detail: `## The 4×4 state — on the diagonal

Salsa20's working state is sixteen 32-bit words, drawn as a 4×4 matrix:

|   |   |   |   |
|---|---|---|---|
| **c0** | k0 | k1 | k2 |
| k3 | **c1** | n0 | n1 |
| t0 | t1 | **c2** | k4 |
| k5 | k6 | k7 | **c3** |

The four constants sit on the **main diagonal**; the key fills the two blocks
either side of it; the nonce (n0, n1) and the counter (t0, t1) take the middle.

**This is the cipher's most visible difference from ChaCha20**, whose state is
four neat contiguous regions — constants, then key, then counter, then nonce.
That is why the step you are looking at concatenates **eight** inputs where
ChaCha20's concatenates four:

\`\`\`
c0 ‖ k0..k3 ‖ c1 ‖ nonce ‖ counter ‖ c2 ‖ k4..k7 ‖ c3
\`\`\`

Reading the matrix in row order, those eight runs are exactly what you get.
ChaCha20 rearranged this into regions — a genuine simplification, and one of
the changes Bernstein made when he revised the design.

Notice what is *not* here: any of the message. Salsa20 never encrypts the
plaintext. It builds a keystream from the key, the nonce and a counter, and the
message meets that keystream exactly once, at an XOR, at the very end.

Notice also that only the two counter words change from block to block.`,
  references: ["Bernstein, *Salsa20 specification* (2005), §Salsa20 expansion"],
};

const narrFinalAdd: StepDocumentation = {
  name: "Add the original state",
  summary: "Adds the state as it was before the rounds to the state after them, word by word.",
  detail: `## The feed-forward — and why it is not optional

\`\`\`
output[i] = initial[i] + mixed[i]   (mod 2³², for each of the 16 words)
\`\`\`

The twenty rounds are built from addition, rotation and XOR, and **every one of
those operations is reversible**. Run them backwards and the initial state comes
back — including the key sitting in words 1–4 and 11–14.

So without this step the cipher would be catastrophically broken: an attacker
who saw 64 bytes of keystream could simply invert the rounds and read the key
straight out.

Adding the original state back in is what destroys that. The result is a one-way
function of the input: to invert the rounds you would need the mixed state, and
to get the mixed state from the output you would need the initial state, which
is exactly the secret you were trying to find.

This trick — mix reversibly, then add the input back — is the same one that
underlies the compression function of SHA-2 and most other hashes, and ChaCha20
inherits it unchanged.`,
  references: ["Bernstein, *Salsa20 specification* (2005), §The Salsa20 hash function"],
};

const narrKeystream: StepDocumentation = {
  name: "Serialize the keystream",
  summary: "Writes the 16 finished words back out as 64 little-endian bytes.",
  detail: `## Out to bytes

The last of the four little-endian boundaries. The sixteen finished words are
written back out four bytes at a time, lowest byte first, giving 64 bytes of
keystream.

That is the block function complete. Nothing about it depended on the message —
this keystream was fully determined by the key, the nonce and the counter, and
could have been computed before the plaintext existed.`,
  references: ["Bernstein, *Salsa20 specification* (2005), §The Salsa20 hash function"],
};

const narrTrim: StepDocumentation = {
  name: "Trim keystream to this block",
  summary: "Cuts the 64-byte keystream down to the length of the message block it will meet.",
  detail: `## The ragged tail

Every block but possibly the last is a full 64 bytes. The final one is whatever
is left over, and this step cuts the keystream to match it, so the ciphertext
comes out exactly as long as the plaintext — no padding, ever.

**The keystream is trimmed, not the message.** The alternative — pad the short
plaintext block out to 64 bytes, XOR, then cut the result — computes the same
bytes but tells a lie in the trace: you would see a padded plaintext block
entering the XOR, when the whole point of a stream cipher is that the message is
never padded and never has to reach a block boundary.

The discarded keystream bytes are simply never generated into anything. They are
not secret, but they are also never reused: the next message under this key must
use a different nonce, and would get an entirely different keystream.`,
  references: ["Bernstein, *Salsa20 specification* (2005)"],
};

const narrXor = (isDecrypt: boolean): StepDocumentation => ({
  name: isDecrypt ? "Keystream ⊕ ciphertext" : "Keystream ⊕ plaintext",
  summary: isDecrypt
    ? "XORs the keystream with the ciphertext block, recovering the plaintext."
    : "XORs the keystream with the plaintext block, producing the ciphertext.",
  detail: `## The only place the message appears

\`\`\`
${isDecrypt ? "P_i = C_i ⊕ keystream_i" : "C_i = P_i ⊕ keystream_i"}
\`\`\`

Everything before this step ran without any knowledge of the message
whatsoever. This single XOR is the entire encryption.

Which is why **decryption is the same operation**. XOR is its own inverse, so
applying the same keystream a second time undoes it — and the encrypt and
decrypt specs in this explorer are structurally identical. Switch direction and
compare them: you will find no difference at all beyond the labels.

A pleasant consequence, and a dangerous one. Pleasant: there is no separate
decryption routine to implement or get wrong, and no inverse of the round
function is ever needed. Dangerous: encryption provides no integrity. An
attacker who flips a bit in the ciphertext flips exactly the corresponding bit
of the recovered plaintext, and nothing here detects it. That is why the
Salsa20/ChaCha20 family is deployed in practice alongside an authenticator —
Poly1305 — rather than on its own.`,
  references: ["Bernstein, *Salsa20 specification* (2005)", "RFC 8439 §2.8 (AEAD construction)"],
});

const narrIncrement: StepDocumentation = {
  name: "Advance the counter",
  summary: "Adds one to the 64-bit block counter so the next block gets different keystream.",
  detail: `## Counting blocks

\`\`\`
counter_{i+1} = counter_i + 1
\`\`\`

The counter is the only part of the state that changes between blocks, and this
is what changes it. Without it every block would be XORed with the same 64
bytes, and the cipher would collapse into a trivially breakable one.

**This step sees the counter as one 64-bit number**, before it is split into the
state's two words — which is exactly why the carry works when the low half
wraps past 2³².

Because the counter is simply a number the cipher is told, Salsa20 is
**seekable**: to decrypt the tenth block you set the counter to its tenth value
and run the block function once — you do not have to process the nine blocks
before it. That is what lets it encrypt a random-access file or resume a stream,
and it is the property OFB lacks, since OFB's register can only be reached by
running the cipher forward from the start.

Sixty-four bits of counter is 2⁶⁴ blocks — 1 zebibyte — under a single
(key, nonce) pair, which is not a limit anyone reaches. ChaCha20's 32-bit
counter caps out at 256 GiB instead; that is the trade it made for its wider
nonce.`,
  references: ["Bernstein, *Salsa20 specification* (2005)"],
};

// ─── The block function body ──────────────────────────────────────────────

/**
 * Everything that happens inside one iteration: build the state, run the ten
 * double rounds, feed the original state forward, serialize, then meet the
 * message.
 *
 * Note what is loaded INSIDE the loop. Port flow cannot cross a container
 * scope, so the key, nonce and constants are fetched per iteration rather than
 * once outside — and that is honest rather than a workaround: the key really
 * does enter every block's state afresh. Salsa20 has no key schedule at all.
 */
const buildBlockBody = (isDecrypt: boolean): StepNode[] => {
  const blockIn = port(ITERATE_ID, "in"); // this block's message bytes
  const counterIn = port(ITERATE_ID, "chain"); // the 64-bit counter, big-endian

  const nodes: StepNode[] = [
    // ── The eight state runs ──────────────────────────────────────────────
    // Four separate constant loads: Salsa20 puts them on the diagonal, so they
    // are not contiguous and cannot be one step (contrast ChaCha20).
    ...SALSA20_CONSTANT_WORDS.map(
      (bytes, i): StepNode => ({
        kind: "step",
        id: `constant-${i}`,
        type: "constant-load@1",
        params: { bytes: [...bytes] },
        narrationOverride: narrConstants(i),
      }),
    ),
    {
      kind: "step",
      id: "key-bytes",
      type: "aux-load-bytes@1",
      params: { auxName: "key", byteLength: SALSA20_KEY_BYTES },
    },
    {
      kind: "step",
      id: "key-be",
      type: "permute@1",
      params: { indices: wordReverseIndices(SALSA20_KEY_BYTES) },
      portInputs: { input: port("key-bytes", "output") },
      narrationOverride: narrKeyBe,
    },
    // The key is split in half: words 0–3 land at state 1–4, words 4–7 at 11–14.
    {
      kind: "step",
      id: "key-low",
      type: "byte-slice@1",
      params: { sourceByteLength: SALSA20_KEY_BYTES, offset: 0, length: 16 },
      portInputs: { input: port("key-be", "output") },
      narrationOverride: narrKeyHalf(false),
    },
    {
      kind: "step",
      id: "key-high",
      type: "byte-slice@1",
      params: { sourceByteLength: SALSA20_KEY_BYTES, offset: 16, length: 16 },
      portInputs: { input: port("key-be", "output") },
      narrationOverride: narrKeyHalf(true),
    },
    {
      kind: "step",
      id: "iv-bytes",
      type: "aux-load-bytes@1",
      params: { auxName: "iv", byteLength: SALSA20_IV_BYTES },
    },
    // IV layout is [counter: 8][nonce: 8], so the nonce starts at offset 8.
    {
      kind: "step",
      id: "nonce-le",
      type: "byte-slice@1",
      params: {
        sourceByteLength: SALSA20_IV_BYTES,
        offset: SALSA20_COUNTER_BYTES,
        length: SALSA20_NONCE_BYTES,
      },
      portInputs: { input: port("iv-bytes", "output") },
    },
    {
      kind: "step",
      id: "nonce-be",
      type: "permute@1",
      params: { indices: wordReverseIndices(SALSA20_NONCE_BYTES) },
      portInputs: { input: port("nonce-le", "output") },
      narrationOverride: narrNonceBe,
    },
    // The carry arrives as ONE big-endian 64-bit number; the state wants two
    // big-endian words, low half first. Swapping the halves is that conversion.
    // The increment step below reads `counterIn` raw, NOT this.
    {
      kind: "step",
      id: COUNTER_WORDS_ID,
      type: "permute@1",
      params: { indices: [4, 5, 6, 7, 0, 1, 2, 3] },
      portInputs: { input: counterIn },
      narrationOverride: narrCounterWords,
    },
    // The eight runs of the diagonal layout, in state order.
    {
      kind: "step",
      id: STATE_INIT_ID,
      type: "concat@1",
      params: { inputCount: 8 },
      portInputs: {
        input0: port("constant-0", "output"), //  word 0
        input1: port("key-low", "output"), //     words 1–4
        input2: port("constant-1", "output"), //  word 5
        input3: port("nonce-be", "output"), //    words 6–7
        input4: port(COUNTER_WORDS_ID, "output"), // words 8–9
        input5: port("constant-2", "output"), //  word 10
        input6: port("key-high", "output"), //    words 11–14
        input7: port("constant-3", "output"), //  word 15
      },
      narrationOverride: narrStateInit,
    },
  ];

  // ── Ten double rounds ─────────────────────────────────────────────────
  // Note these split into SIXTEEN words, exactly like ChaCha20's. The 8-vs-4
  // difference above is about state ASSEMBLY only; once assembled, the state is
  // sixteen words in both ciphers.
  let stateBinding: PortBinding = port(STATE_INIT_ID, "output");
  for (let dr = 0; dr < DOUBLE_ROUNDS; dr++) {
    const groupId = `double-round.${dr}`;
    const splitId = `${groupId}.split`;
    const concatId = `${groupId}.concat`;

    // Inside the group's fresh scope: the 64-byte seed becomes 16 words.
    const words: PortBinding[] = Array.from({ length: 16 }, (_, i) => port(splitId, `output${i}`));

    const children: StepNode[] = [
      {
        kind: "step",
        id: splitId,
        type: "split-bytes@1",
        params: { widths: [...STATE_WORD_WIDTHS] },
        portInputs: { input: port(groupId, "in") },
      },
    ];

    QUARTER_ROUND_INDICES.forEach((quad, qr) => {
      children.push(...quarterRound(`${groupId}.qr${qr}`, words, quad));
    });

    children.push({
      kind: "step",
      id: concatId,
      type: "concat@1",
      params: { inputCount: 16 },
      portInputs: Object.fromEntries(words.map((w, i) => [`input${i}`, w])),
    });

    nodes.push({
      kind: "group",
      id: groupId,
      label: `Double round ${dr + 1} of ${DOUBLE_ROUNDS} (column round then row round)`,
      // 98 leaves apiece; uncollapsed by default this is a wall of chips.
      defaultCollapsed: true,
      seedInput: stateBinding,
      bodyOutput: port(concatId, "output"),
      children,
    });

    stateBinding = port(groupId, "out");
  }

  // ── Feed-forward, serialize, and meet the message ─────────────────────
  nodes.push(
    {
      // One leaf, not sixteen: `add-mod-32@1` adds word-wise across the whole
      // buffer, so a single frame is exactly "add the original input words to
      // the output words".
      kind: "step",
      id: FINAL_ADD_ID,
      type: "add-mod-32@1",
      params: { inputCount: 2 },
      portInputs: { operand0: stateBinding, operand1: port(STATE_INIT_ID, "output") },
      narrationOverride: narrFinalAdd,
    },
    {
      kind: "step",
      id: KEYSTREAM_ID,
      type: "permute@1",
      params: { indices: wordReverseIndices(SALSA20_BLOCK_BYTES) },
      portInputs: { input: port(FINAL_ADD_ID, "output") },
      narrationOverride: narrKeystream,
    },
    {
      kind: "step",
      id: TRIM_ID,
      type: "truncate-to-reference@1",
      params: {},
      portInputs: { input: port(KEYSTREAM_ID, "output"), reference: blockIn },
      narrationOverride: narrTrim,
    },
    {
      kind: "step",
      id: XOR_ID,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: { operand0: blockIn, operand1: port(TRIM_ID, "output") },
      narrationOverride: narrXor(isDecrypt),
    },
    {
      // Reads the counter AS IT ARRIVED — the raw 64-bit carry, parallel to the
      // block function rather than downstream of it, which is why Salsa20 blocks
      // are independent and could be computed in any order, or in parallel.
      // `increment-counter@1` derives its width from the wired input, so this is
      // a 64-bit increment carrying from word 8 into word 9.
      kind: "step",
      id: INCREMENT_ID,
      type: "increment-counter@1",
      params: {},
      portInputs: { counter: counterIn },
      narrationOverride: narrIncrement,
    },
  );

  return nodes;
};

// ─── The spec ─────────────────────────────────────────────────────────────

/**
 * Build the Salsa20/20 spec.
 *
 * @param direction spec id, name and prose only — both directions build
 *                  structurally identical specs (see the file header)
 */
export function buildSalsa20Spec(direction: SalsaDirection): CipherSpec {
  const isDecrypt = direction === "decrypt";

  return {
    id: `salsa20${isDecrypt ? "-decrypt" : ""}@1`,
    name: `Salsa20${isDecrypt ? " (decrypt)" : ""}`,
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: SALSA20_KEY_BYTES },
    },
    steps: [
      // The counter bootstrap lives OUTSIDE the loop: `aux["iv"]`'s first eight
      // bytes, reversed AS ONE 64-BIT NUMBER, become the value the iterate's
      // carry starts at.
      {
        kind: "step",
        id: "iv-source",
        type: "aux-load-bytes@1",
        params: { auxName: "iv", byteLength: SALSA20_IV_BYTES },
      },
      {
        kind: "step",
        id: "counter-le",
        type: "byte-slice@1",
        params: { sourceByteLength: SALSA20_IV_BYTES, offset: 0, length: SALSA20_COUNTER_BYTES },
        portInputs: { input: port("iv-source", "output") },
      },
      {
        // All eight bytes reversed together — NOT two 4-byte word reversals.
        // The counter is a single 64-bit integer and must carry across its
        // halves; see the file header.
        kind: "step",
        id: COUNTER_INIT_ID,
        type: "permute@1",
        params: { indices: [7, 6, 5, 4, 3, 2, 1, 0] },
        portInputs: { input: port("counter-le", "output") },
        narrationOverride: narrCounterInit,
      },
      {
        kind: "iterate",
        id: ITERATE_ID,
        label: "Salsa20 blocks (keystream ⊕ message)",
        seedInput: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
        blockByteLength: SALSA20_BLOCK_BYTES,
        // A stream cipher accepts any length ≥ 1; the final block may be short
        // and `salsa-trim` matches the keystream to it.
        allowPartialFinalBlock: true,
        chainInput: port(COUNTER_INIT_ID, "output"),
        chainFeedback: port(INCREMENT_ID, "output"),
        bodyOutput: port(XOR_ID, "output"),
        outputPorts: ["out"],
        children: buildBlockBody(isDecrypt),
      },
    ],
    outputFrom: port(ITERATE_ID, "out"),
  };
}

/** Salsa20/20 encryption. */
export const salsa20EncryptSpec: CipherSpec = buildSalsa20Spec("encrypt");
/** Salsa20/20 decryption — byte-identical structure; see the file header. */
export const salsa20DecryptSpec: CipherSpec = buildSalsa20Spec("decrypt");
