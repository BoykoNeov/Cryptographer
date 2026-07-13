/**
 * SHA3-256 cipher spec — the first sponge-based hash and the first SHA-3 /
 * Keccak function in the app (FIPS 202), 2026-07-13. Foundation slice for
 * future post-quantum work (ML-KEM / ML-DSA consume SHAKE, which reuses this
 * exact Keccak-f[1600] permutation).
 *
 * **Sponge, not Merkle–Damgård.** Where SHA-256 folds each block into a small
 * chaining value with a compression function, SHA-3 keeps a large 1600-bit
 * (200-byte) **state** and:
 *   - **absorbs** the padded message `rate` bytes (136 for SHA3-256) at a time,
 *     XORing each block into the first `rate` bytes of the state and then
 *     running the Keccak-f[1600] permutation;
 *   - **squeezes** the digest out of the state (for SHA3-256 the 32-byte digest
 *     fits in one `rate`-block, so a single squeeze = slice the first 32 bytes;
 *     no XOF loop — that is SHAKE's job, see `shake.ts`).
 *
 * **Shared Keccak-f machinery.** The permutation (θ→ρ→π→χ→ι round builder), the
 * geometry + round constants, and the absorb XOR-fold live in `keccak-f.ts`,
 * shared with SHAKE. This file supplies only SHA3-256's rate (136), domain byte
 * (0x06), digest length (32), and the pad/init/absorb/squeeze narration prose.
 * The absorb 24 rounds are built with an EMPTY prefix so their ids stay
 * `round.0`…`round.23` — byte-identical to the pre-extraction spec.
 *
 * **Reuses SHA-256's port-native machinery.** The absorb loop is the SAME
 * port-mode `iterate` fold SHA-256's multi-block hashing uses: the carried
 * chain is the full 200-byte state (`chainInput` bootstraps it to all-zeros,
 * `chainFeedback` advances it, `chainOutput` harvests the final state). Each
 * block arrives on `port("sponge","in")`, the running state on
 * `port("sponge","chain")`.
 *
 * **KAT.** The whole assembled sponge is byte-equal to `node:crypto`'s
 * `sha3-256` across all message lengths (`tests/sha3-256-kat.test.ts`),
 * including the empty message (`a7ffc6f8…f8434a`), the one-byte-short-of-a-block
 * pad-merge case, and multi-block messages.
 *
 * **References:**
 *   - FIPS 202 §4    — the sponge construction
 *   - FIPS 202 §5.1  — pad10*1; §B.2 — domain separation (0x06 for SHA-3)
 *   - FIPS 202 §A.1  — SHA3-256 examples / KATs
 */

import type { CipherSpec, StepDocumentation } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import type { AbsorbNarration } from "./keccak-f";
import {
  RC_BYTES,
  ROUNDS,
  S0_BYTES,
  STATE_BYTES,
  buildAbsorbSteps,
  buildKeccakRounds,
  port,
} from "./keccak-f";

// ─── SHA3-256 sponge parameters ─────────────────────────────────────────────

const RATE = 136; // sponge rate in bytes (1088 bits); capacity = 64 bytes
const DIGEST_BYTES = 32;
const DOMAIN_SHA3 = 0x06;

// ─── narrationOverride: SHA3-256-specific prose (rate/domain-specific) ───────
//
// The Keccak-f round prose (θρπχι) is shared from `keccak-f.ts`; these blocks
// carry SHA3-256's rate (136) / domain (0x06) / fixed-digest wording, which
// differs from SHAKE's (168/136 rate, 0x1F domain, extendable output).

const NARR_PAD: StepDocumentation = {
  name: "Pad + domain-separate (pad10*1, FIPS 202 §5.1)",
  summary:
    "Append the SHA-3 domain byte 0x06 and pad with the 10*1 rule to a multiple of the 136-byte rate.",
  detail: `SHA-3 extends the message to a whole number of 136-byte sponge
blocks: append the domain byte \`0x06\` (which also carries the padding's
leading 1-bit), zero-fill, then set the top bit of the last byte. Unlike
SHA-256 there is **no length suffix** — the sponge's security comes from the
capacity, not from encoding the length. When the message is one byte short of a
block the two pad bits merge into a single \`0x86\` byte.`,
  references: ["FIPS 202 §5.1 (pad10*1)", "FIPS 202 §B.2 (domain separation)"],
};

const NARR_INIT_STATE: StepDocumentation = {
  name: "Initial sponge state (200 zero bytes)",
  summary: "Bootstrap the absorb fold with an all-zero 1600-bit state.",
  detail: `The sponge starts from the all-zero state (FIPS 202 §4). This leaf
loads the 200 zero bytes that seed the per-block fold's running state — the
Keccak analogue of SHA-256's initial hash values, but simpler: there are no
magic constants, the state just starts empty and every bit of structure comes
from absorbing the message and permuting.`,
  references: ["FIPS 202 §4 (sponge construction)"],
};

const NARR_ABSORB_SPLIT: StepDocumentation = {
  name: "Split state into rate (136) + capacity (64)",
  summary:
    "Separate the running state's absorbing part (first 136 bytes) from its hidden capacity (last 64).",
  detail: `The sponge only mixes the message into the **rate** portion — the
first 136 bytes. The remaining 64 bytes are the **capacity**, never touched
directly by the message; that hidden part is exactly what gives SHA-3 its
resistance to collision and preimage attacks. This split separates the two so
the next step XORs the block into the rate only.`,
  references: ["FIPS 202 §4 (rate and capacity)"],
};

const NARR_ABSORB_XOR: StepDocumentation = {
  name: "Absorb: XOR this block into the rate",
  summary: "XOR the 136-byte message block into the first 136 bytes of the state.",
  detail: `Absorbing a block means XORing it into the rate portion of the state
(FIPS 202 §4). This is the only place the message enters the sponge. After the
XOR the whole state is permuted, spreading the block's influence across all 1600
bits before the next block arrives.`,
  references: ["FIPS 202 §4 (absorbing)"],
};

const NARR_ABSORB_CONCAT: StepDocumentation = {
  name: "Reassemble the 200-byte state",
  summary: "Join the message-XORed rate back with the untouched capacity.",
  detail: `Rejoins the freshly-absorbed 136-byte rate with the 64-byte capacity
to form the full 200-byte state that the Keccak-f permutation will scramble.`,
  references: ["FIPS 202 §4 (sponge construction)"],
};

const ABSORB_NARRATION: AbsorbNarration = {
  split: NARR_ABSORB_SPLIT,
  xor: NARR_ABSORB_XOR,
  concat: NARR_ABSORB_CONCAT,
};

const NARR_SQUEEZE: StepDocumentation = {
  name: "Squeeze the 256-bit digest",
  summary: "Take the first 32 bytes of the final state as the SHA3-256 output.",
  detail: `After the last block is absorbed, SHA-3 **squeezes** the digest out of
the state. For SHA3-256 the 32-byte output fits inside the 136-byte rate, so a
single squeeze suffices: the digest is simply the first 32 bytes of the final
state (FIPS 202 §4). SHAKE, whose output can be arbitrarily long, repeats the
squeeze-and-permute loop — that is a later slice.`,
  references: ["FIPS 202 §4 (squeezing)", "FIPS 202 §A.1 (SHA3-256 examples)"],
};

// ─── Spec builder ────────────────────────────────────────────────────────────

/**
 * Build the SHA3-256 spec: pad → sponge-absorb fold (Keccak-f[1600] per block)
 * → squeeze the first 32 bytes.
 */
export const buildSha3256Spec = (): CipherSpec => ({
  id: "sha3-256@1",
  name: "SHA3-256",
  stateShape: "bytes",
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 0 }, // hashes have no key
  },
  steps: [
    // ─── Padding (pad10*1 + domain byte 0x06) ────────────────────────────
    {
      kind: "step",
      id: "pad",
      type: "keccak.pad@1",
      params: { rate: RATE, domainByte: DOMAIN_SHA3 },
      portInputs: { input: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT) },
      narrationOverride: NARR_PAD,
    },
    // ─── Initial all-zero sponge state (the fold's chainInput) ───────────
    {
      kind: "step",
      id: "init-state",
      type: "aux-load-bytes@1",
      params: { auxName: "S0", byteLength: STATE_BYTES },
      narrationOverride: NARR_INIT_STATE,
    },
    // ─── Sponge absorb fold (one Keccak-f[1600] per rate block) ──────────
    // Port-mode iterate: seedInput = padded message (split into 136-byte
    // blocks), chain = the running 200-byte state, chainOutput harvests the
    // final state for squeezing.
    {
      kind: "iterate",
      id: "sponge",
      label: "Sponge absorb (Keccak-f[1600] per block)",
      blockByteLength: RATE,
      seedInput: port("pad", "output"),
      chainInput: port("init-state", "output"),
      chainFeedback: port(`round.${ROUNDS - 1}`, "out"),
      bodyOutput: port(`round.${ROUNDS - 1}`, "out"),
      chainOutput: "state",
      children: [
        ...buildAbsorbSteps(RATE, ABSORB_NARRATION),
        ...buildKeccakRounds("", port("absorb", "output")),
      ],
    },
    // ─── Squeeze: first 32 bytes of the final state = the digest ─────────
    {
      kind: "step",
      id: "squeeze",
      type: "byte-slice@1",
      params: { sourceByteLength: STATE_BYTES, offset: 0, length: DIGEST_BYTES },
      portInputs: { input: port("sponge", "state") },
      narrationOverride: NARR_SQUEEZE,
    },
  ],
  // Published constants materialized into aux before the walk: RC (24-lane
  // round-constant table) + S0 (the all-zero initial state).
  cipherConstants: { RC: RC_BYTES, S0: S0_BYTES },
  outputFrom: port("squeeze", "output"),
});
