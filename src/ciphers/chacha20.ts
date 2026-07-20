/**
 * ChaCha20 (RFC 8439) — the app's first STREAM cipher.
 *
 * Every other cipher here is a block cipher with a `BlockCipherCore`, and the
 * mode machinery (`modes/ecb.ts`, `cbc.ts`, `ctr.ts`, `cfb.ts`, `ofb.ts`) is
 * built on that contract. ChaCha20 has no core and needs none: it is not a
 * permutation that a mode wraps, it is a **keystream generator** that already
 * contains its own counter. What it borrows from CTR is not the code but the
 * shape — an `iterate` over fixed-width blocks, a counter riding the loop's
 * cross-iteration carry, a `truncate-to-reference@1` for the ragged tail, and
 * an `xor@1` where the message finally appears.
 *
 * That it works at all is the point worth noticing: the port-mode `iterate` in
 * `core/runtime.ts` mentions no cipher, no core and no mode. It splits a seed
 * into blocks, runs a body, and carries one value across iterations. ChaCha20
 * reaches all of that without a `BlockCipherCore` in sight.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * ENDIANNESS — read this before editing anything below.
 *
 * ChaCha20 is natively LITTLE-endian: its key, nonce, counter and keystream
 * are all little-endian 32-bit words. The app's ARX primitives (`add-mod-32@1`,
 * `rotate-bits-left@1`) are BIG-endian. Rather than fork the vocabulary, this
 * builder follows the convention Twofish established
 * (`twofish-spec-builder.ts`): **words travel the ports big-endian, and every
 * LE↔BE crossing is a visible `permute@1` word-reversal at an endpoint.**
 * There are exactly four such crossings, and they are the only places byte
 * order is touched:
 *
 *   1. `key-be`      — the 32-byte key,   8 word reversals
 *   2. `nonce-be`    — the 12-byte nonce, 3 word reversals
 *   3. `counter-init`— the 4-byte counter, 1 word reversal (outside the loop)
 *   4. `keystream`   — the 64-byte output, 16 word reversals
 *
 * Between them everything is big-endian and the arithmetic primitives are used
 * unmodified. A rotation is defined on the 32-bit *value*, so `<<< 12` is
 * `<<< 12` under either serialization — this is a serialization convention,
 * not a change to the cipher.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * WHY DOUBLE ROUNDS ARE GROUPS AND QUARTER-ROUNDS ARE NOT.
 *
 * A group body starts a FRESH port scope, seeded with exactly one value
 * (`port(groupId, "in")`). A quarter-round consumes four words, so a
 * per-quarter-round group is not representable without inventing concat/split
 * plumbing that appears nowhere in the RFC — the same constraint that keeps
 * Twofish's 4-rail rounds flat at top level.
 *
 * A DOUBLE round, though, consumes and produces the whole 64-byte state — one
 * value. So the ten double rounds are genuine groups (split → 8 quarter-rounds
 * → concat), and the split/concat at their boundary is honest rather than
 * plumbing: the state really is 64 bytes there. That also matches how the RFC
 * counts: "20 rounds" is 10 iterations of a column round plus a diagonal round.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * ENCRYPT AND DECRYPT ARE THE SAME SPEC. The message meets only an XOR, and
 * XOR is its own inverse — CTR's and OFB's symmetry. `direction` therefore
 * affects the spec id, name and prose ONLY.
 *
 * The consequence for testing is the one OFB documented: **round-tripping this
 * cipher proves nothing.** One spec used both ways round-trips by construction
 * even if the quarter-round is entirely wrong. The verification budget goes to
 * RFC 8439's published vectors and `node:crypto` instead — see
 * `tests/chacha20-kat.test.ts`.
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

export type ChaChaDirection = "encrypt" | "decrypt";

// ─── Constants ────────────────────────────────────────────────────────────

/** The cipher's block width: 64 bytes of keystream per counter value. */
export const CHACHA20_BLOCK_BYTES = 64;
/** RFC 8439 fixes the key at 256 bits. */
export const CHACHA20_KEY_BYTES = 32;
/** The 16-byte `aux["iv"]` blob: a 4-byte LE counter then a 12-byte nonce. */
export const CHACHA20_IV_BYTES = 16;

/**
 * The four constant words at state positions 0–3, big-endian on the wire.
 *
 * RFC 8439 §2.3 gives them as `0x61707865, 0x3320646e, 0x79622d32, 0x6b206574`
 * — which is the little-endian reading of the ASCII string "expand 32-byte k".
 * Because words travel big-endian here, the bytes below are each word's
 * big-endian encoding — which is the ASCII group REVERSED. Read as text the
 * array spells "apxe" "3 dn" "yb-2" "k et"; reversing each group again recovers
 * "expa" "nd 3" "2-by" "te k". (This comment previously claimed the array read
 * back as the string directly, which is wrong: 0x61 is 'a', not 'e'.)
 *
 * These are a nothing-up-my-sleeve number: a fixed, public, obviously
 * arbitrary value that could not have been chosen to hide a weakness. They
 * also pin one quarter of the state to a value an attacker cannot influence.
 */
export const CHACHA20_CONSTANTS: readonly number[] = [
  0x61, 0x70, 0x78, 0x65, 0x33, 0x20, 0x64, 0x6e, 0x79, 0x62, 0x2d, 0x32, 0x6b, 0x20, 0x65, 0x74,
];

/**
 * RFC 8439 §2.3.1: one double round is four COLUMN quarter-rounds followed by
 * four DIAGONAL ones, and the block function runs this ten times for its
 * twenty rounds.
 *
 * The column round mixes each of the state matrix's four columns independently;
 * the diagonal round then mixes along the four diagonals. Alternating the two
 * is what spreads a change in any one word to every other word — after a
 * column round a difference has reached the whole column, and the diagonal
 * round then carries it into every other column.
 */
const QUARTER_ROUND_INDICES: readonly (readonly [number, number, number, number])[] = [
  // Column round.
  [0, 4, 8, 12],
  [1, 5, 9, 13],
  [2, 6, 10, 14],
  [3, 7, 11, 15],
  // Diagonal round.
  [0, 5, 10, 15],
  [1, 6, 11, 12],
  [2, 7, 8, 13],
  [3, 4, 9, 14],
];

const DOUBLE_ROUNDS = 10;

// Node ids referenced from more than one place.
const ITERATE_ID = "chacha-blocks";
const STATE_INIT_ID = "state-init";
const FINAL_ADD_ID = "final-add";
const KEYSTREAM_ID = "keystream";
const TRIM_ID = "chacha-trim";
const XOR_ID = "chacha-xor";
const INCREMENT_ID = "chacha-increment";
const COUNTER_INIT_ID = "counter-init";

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
 * RFC 8439 §2.1. The quarter round is ChaCha20's entire nonlinear engine —
 * everything else in the cipher is bookkeeping about which four words to feed
 * it. Given words (a, b, c, d):
 *
 * ```
 *   a += b;  d ^= a;  d <<<= 16;
 *   c += d;  b ^= c;  b <<<= 12;
 *   a += b;  d ^= a;  d <<<= 8;
 *   c += d;  b ^= c;  b <<<= 7;
 * ```
 *
 * Twelve operations, drawn from exactly three kinds: Addition, Rotation, XOR
 * — the ARX family. There is no S-box and no lookup table, which is precisely
 * the design goal: every operation runs in constant time on ordinary CPU
 * registers, so the cipher has no cache-timing side channel of the sort that
 * table-driven designs like AES have to be implemented very carefully to avoid.
 *
 * The three operations do different jobs, and the cipher needs all three.
 * Addition carries left, mixing low bits into high ones. XOR mixes bit-for-bit
 * with no carry. Rotation moves high bits back down to the bottom, so the next
 * addition's carries reach the bits that just moved. Any two of the three
 * would leave a structure an attacker could exploit; alternating all three is
 * what makes the mixing hard to unpick.
 *
 * @param idPrefix unique per (double round, quarter round) — ids are trace keys
 * @param words    the live 16-word binding table, MUTATED in place at a/b/c/d
 * @param a,b,c,d  which four state words this quarter round mixes
 */
const quarterRound = (
  idPrefix: string,
  words: PortBinding[],
  [a, b, c, d]: readonly [number, number, number, number],
): StepNode[] => {
  const nodes: StepNode[] = [];

  /** a += b (word-wise, mod 2³²). */
  const add = (id: string, x: number, y: number): void => {
    const nodeId = `${idPrefix}.${id}`;
    nodes.push({
      kind: "step",
      id: nodeId,
      type: "add-mod-32@1",
      params: { inputCount: 2 },
      portInputs: { operand0: words[x] as PortBinding, operand1: words[y] as PortBinding },
    });
    words[x] = port(nodeId, "output");
  };

  /** d ^= a. */
  const xorInto = (id: string, x: number, y: number): void => {
    const nodeId = `${idPrefix}.${id}`;
    nodes.push({
      kind: "step",
      id: nodeId,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: { operand0: words[x] as PortBinding, operand1: words[y] as PortBinding },
    });
    words[x] = port(nodeId, "output");
  };

  /**
   * d <<<= n. The `bits` value here is the RFC's own number — 16, 12, 8, 7 —
   * which is the entire reason `rotate-bits-left@1` exists rather than reusing
   * the right-handed primitive at the complement.
   */
  const rotate = (id: string, x: number, bits: number): void => {
    const nodeId = `${idPrefix}.${id}`;
    nodes.push({
      kind: "step",
      id: nodeId,
      type: "rotate-bits-left@1",
      params: { bits, wordBits: 32 },
      portInputs: { input: words[x] as PortBinding },
    });
    words[x] = port(nodeId, "output");
  };

  add("add-ab-1", a, b);
  xorInto("xor-da-1", d, a);
  rotate("rot-d-16", d, 16);
  add("add-cd-1", c, d);
  xorInto("xor-bc-1", b, c);
  rotate("rot-b-12", b, 12);
  add("add-ab-2", a, b);
  xorInto("xor-da-2", d, a);
  rotate("rot-d-8", d, 8);
  add("add-cd-2", c, d);
  xorInto("xor-bc-2", b, c);
  rotate("rot-b-7", b, 7);

  return nodes;
};

// ─── Narration for the structural leaves ──────────────────────────────────

const narrConstants: StepDocumentation = {
  name: "Load the constants",
  summary: 'The four fixed words "expand 32-byte k" that begin every ChaCha20 state.',
  detail: `## The constants

\`\`\`
"expa"  "nd 3"  "2-by"  "te k"
\`\`\`

The first four of the state's sixteen words are always these, for every key,
every nonce and every message. They spell the ASCII string \`expand 32-byte k\`.

This is a **nothing-up-my-sleeve number**: a value so obviously arbitrary that
its designer could not plausibly have chosen it to hide a weakness. A constant
that looked random would invite the question "why *that* one?"; an English
sentence does not.

They also do real work. A quarter of the state is fixed at a value the attacker
cannot influence, no matter what key, nonce or counter is supplied — so no
choice of inputs can drive the whole state to a value of the attacker's
choosing.`,
  references: ["RFC 8439 §2.3 (ChaCha20 state)"],
};

const narrKeyBe: StepDocumentation = {
  name: "Key → words",
  summary: "Reads the 32-byte key as eight 32-bit words, reversing each word's bytes.",
  detail: `## Reading the key as words

The key arrives as 32 bytes. ChaCha20 works on 32-bit words, so those bytes are
read four at a time — and ChaCha20 reads them **little-endian**, meaning the
first byte is the word's *lowest* 8 bits, not its highest.

This explorer moves words between steps big-endian, so each group of four bytes
is reversed here. Every byte of the key is still present and still in its own
word; only the order within each word changes.

That is what this step is: the boundary where the cipher's little-endian
convention meets the explorer's big-endian one. There are four such boundaries
in the whole cipher — this one, the nonce, the counter, and the keystream on
the way out — and nothing between them touches byte order again.`,
  references: ["RFC 8439 §2.3 (ChaCha20 state)"],
};

const narrNonceBe: StepDocumentation = {
  name: "Nonce → words",
  summary: "Reads the 12-byte nonce as three 32-bit words, reversing each word's bytes.",
  detail: `## The nonce

A **nonce** is a "number used once". It does not need to be secret and it does
not need to be unpredictable — but it must never repeat for a given key.

That single rule is doing an enormous amount of work. The keystream depends
only on the key, the nonce and the counter. Encrypt two different messages
under the same key AND the same nonce and they get the *same* keystream; XOR
the two ciphertexts together and the keystream cancels, leaving the two
plaintexts XORed with each other. That is recoverable, and it has broken real
systems.

Twelve bytes is 96 bits, which is comfortably large enough to pick nonces at
random without a realistic chance of collision — but the safest schemes simply
count.`,
  references: ["RFC 8439 §2.3", "RFC 8439 §4 (security considerations)"],
};

const narrCounterInit: StepDocumentation = {
  name: "Initial counter",
  summary: "The first four IV bytes, read as the little-endian 32-bit starting counter.",
  detail: `## Where the counter comes from

The IV field supplies 16 bytes, laid out the way OpenSSL lays them out:

\`\`\`
[ counter: 4 bytes, little-endian ][ nonce: 12 bytes ]
\`\`\`

This step takes the first four and reads them as the starting block counter,
reversing the bytes for the same little-endian reason as the key and the nonce.

**RFC 8439's own test vectors start this counter at 1, not 0.** The choice is
free — any starting value works, as long as encryption and decryption agree —
but it is a classic source of a bug that is very hard to see: a cipher that
starts at the wrong counter produces perfectly plausible ciphertext that simply
will not decrypt anywhere else.`,
  references: ["RFC 8439 §2.4 (ChaCha20 encryption)", "RFC 8439 §2.4.2 (test vector)"],
};

const narrStateInit: StepDocumentation = {
  name: "Assemble the state",
  summary: "The four state regions — constants, key, counter, nonce — concatenated into 16 words.",
  detail: `## The 4×4 state

ChaCha20's entire working state is sixteen 32-bit words, conventionally drawn
as a 4×4 matrix and assembled from exactly four sources:

| words | contents |
|---|---|
| 0–3   | the constants \`"expand 32-byte k"\` |
| 4–11  | the 256-bit key |
| 12    | the block counter |
| 13–15 | the 96-bit nonce |

Notice what is *not* here: any of the message. ChaCha20 never encrypts the
plaintext. It builds a keystream out of the key, the nonce and a counter, and
the message meets that keystream exactly once, at an XOR, at the very end.

Notice also that only word 12 changes from block to block. The key and nonce
are fixed for the whole message, so every block's state differs from the last
in one word — and the twenty rounds that follow have to turn that one-word
difference into 64 bytes of unrelated-looking keystream.`,
  references: ["RFC 8439 §2.3 (ChaCha20 state)"],
};

const narrFinalAdd: StepDocumentation = {
  name: "Add the original state",
  summary: "Adds the state as it was before the rounds to the state after them, word by word.",
  detail: `## The feed-forward — and why it is not optional

\`\`\`
output[i] = initial[i] + mixed[i]   (mod 2³², for each of the 16 words)
\`\`\`

The twenty rounds are built from addition, rotation and XOR, and **every one of
those operations is reversible**. Run them backwards and the initial state
comes back — including the key sitting in words 4–11.

So without this step the cipher would be catastrophically broken: an attacker
who saw 64 bytes of keystream could simply invert the rounds and read the key
straight out.

Adding the original state back in is what destroys that. The result is a
one-way function of the input: to invert the rounds you would need the mixed
state, and to get the mixed state from the output you would need the initial
state, which is exactly the secret you were trying to find.

This trick — mix reversibly, then add the input back — is the same one that
underlies the compression function of SHA-2 and most other hashes.`,
  references: ["RFC 8439 §2.3 (ChaCha20 block function)"],
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
  references: ["RFC 8439 §2.3 (ChaCha20 block function)"],
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
entering the XOR, when the whole point of a stream cipher is that the message
is never padded and never has to reach a block boundary.

The discarded keystream bytes are simply never generated into anything. They
are not secret, but they are also never reused: the next message under this key
must use a different nonce, and would get an entirely different keystream.`,
  references: ["RFC 8439 §2.4 (ChaCha20 encryption)"],
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
of the recovered plaintext, and nothing here detects it. That is why ChaCha20
is deployed in practice as ChaCha20-Poly1305, paired with an authenticator.`,
  references: ["RFC 8439 §2.4", "RFC 8439 §2.8 (AEAD construction)"],
});

const narrIncrement: StepDocumentation = {
  name: "Advance the counter",
  summary: "Adds one to the block counter so the next block gets different keystream.",
  detail: `## Counting blocks

\`\`\`
counter_{i+1} = counter_i + 1
\`\`\`

The counter is the only part of the state that changes between blocks, and this
is what changes it. Without it every block would be XORed with the same 64
bytes, and the cipher would collapse into a trivially breakable one.

Because the counter is simply a number the cipher is told, ChaCha20 is
**seekable**: to decrypt the tenth block you set the counter to its tenth value
and run the block function once — you do not have to process the nine blocks
before it. That is what lets it encrypt a random-access file or resume a
stream, and it is the property OFB lacks, since OFB's register can only be
reached by running the cipher forward from the start.

The counter is 32 bits and does not carry into the nonce, which caps one
(key, nonce) pair at 2³² blocks — 256 GiB. Past that it would wrap and repeat
keystream, so a new nonce is required.`,
  references: ["RFC 8439 §2.4"],
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
 * does enter every block's state afresh. ChaCha20 has no key schedule at all,
 * which is one of the reasons it is so fast in software.
 */
const buildBlockBody = (isDecrypt: boolean): StepNode[] => {
  const blockIn = port(ITERATE_ID, "in"); // this block's message bytes
  const counterIn = port(ITERATE_ID, "chain"); // the block counter, big-endian

  const nodes: StepNode[] = [
    // ── The four state regions ────────────────────────────────────────────
    {
      kind: "step",
      id: "constants",
      type: "constant-load@1",
      params: { bytes: [...CHACHA20_CONSTANTS] },
      narrationOverride: narrConstants,
    },
    {
      kind: "step",
      id: "key-bytes",
      type: "aux-load-bytes@1",
      params: { auxName: "key", byteLength: CHACHA20_KEY_BYTES },
    },
    {
      kind: "step",
      id: "key-be",
      type: "permute@1",
      params: { indices: wordReverseIndices(CHACHA20_KEY_BYTES) },
      portInputs: { input: port("key-bytes", "output") },
      narrationOverride: narrKeyBe,
    },
    {
      kind: "step",
      id: "iv-bytes",
      type: "aux-load-bytes@1",
      params: { auxName: "iv", byteLength: CHACHA20_IV_BYTES },
    },
    {
      kind: "step",
      id: "nonce-le",
      type: "byte-slice@1",
      params: { sourceByteLength: CHACHA20_IV_BYTES, offset: 4, length: 12 },
      portInputs: { input: port("iv-bytes", "output") },
    },
    {
      kind: "step",
      id: "nonce-be",
      type: "permute@1",
      params: { indices: wordReverseIndices(12) },
      portInputs: { input: port("nonce-le", "output") },
      narrationOverride: narrNonceBe,
    },
    // constants ‖ key ‖ counter ‖ nonce — the RFC's four regions, in order.
    {
      kind: "step",
      id: STATE_INIT_ID,
      type: "concat@1",
      params: { inputCount: 4 },
      portInputs: {
        input0: port("constants", "output"),
        input1: port("key-be", "output"),
        input2: counterIn,
        input3: port("nonce-be", "output"),
      },
      narrationOverride: narrStateInit,
    },
  ];

  // ── Ten double rounds ─────────────────────────────────────────────────
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
      label: `Double round ${dr + 1} of ${DOUBLE_ROUNDS} (rounds ${2 * dr + 1}–${2 * dr + 2})`,
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
      // buffer, so a single frame is exactly the RFC's "add the original input
      // words to the output words".
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
      params: { indices: wordReverseIndices(CHACHA20_BLOCK_BYTES) },
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
      // Reads the counter AS IT ARRIVED, parallel to the block function rather
      // than downstream of it — which is why ChaCha20 blocks are independent
      // and could be computed in any order, or in parallel.
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
 * Build the ChaCha20 spec.
 *
 * @param direction spec id, name and prose only — both directions build
 *                  structurally identical specs (see the file header)
 */
export function buildChaCha20Spec(direction: ChaChaDirection): CipherSpec {
  const isDecrypt = direction === "decrypt";

  return {
    id: `chacha20${isDecrypt ? "-decrypt" : ""}@1`,
    name: `ChaCha20${isDecrypt ? " (decrypt)" : ""}`,
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: CHACHA20_KEY_BYTES },
    },
    steps: [
      // The counter bootstrap lives OUTSIDE the loop: `aux["iv"]`'s first four
      // bytes, byte-reversed, become the value the iterate's carry starts at.
      {
        kind: "step",
        id: "iv-source",
        type: "aux-load-bytes@1",
        params: { auxName: "iv", byteLength: CHACHA20_IV_BYTES },
      },
      {
        kind: "step",
        id: "counter-le",
        type: "byte-slice@1",
        params: { sourceByteLength: CHACHA20_IV_BYTES, offset: 0, length: 4 },
        portInputs: { input: port("iv-source", "output") },
      },
      {
        kind: "step",
        id: COUNTER_INIT_ID,
        type: "permute@1",
        params: { indices: wordReverseIndices(4) },
        portInputs: { input: port("counter-le", "output") },
        narrationOverride: narrCounterInit,
      },
      {
        kind: "iterate",
        id: ITERATE_ID,
        label: "ChaCha20 blocks (keystream ⊕ message)",
        seedInput: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
        blockByteLength: CHACHA20_BLOCK_BYTES,
        // A stream cipher accepts any length ≥ 1; the final block may be short
        // and `chacha-trim` matches the keystream to it.
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

/** ChaCha20 encryption. */
export const chacha20EncryptSpec: CipherSpec = buildChaCha20Spec("encrypt");
/** ChaCha20 decryption — byte-identical structure; see the file header. */
export const chacha20DecryptSpec: CipherSpec = buildChaCha20Spec("decrypt");
