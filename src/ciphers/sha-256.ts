/**
 * SHA-256 cipher spec — first port-native cipher under the universal-port
 * dataflow plan. Rewritten in Slice 2.6d (2026-05-25) using decomposed
 * port-native compositions of the universal vocabulary (rotate-bits-right,
 * shift-bits-right, xor, add-mod-32, and, not, concat, split-bytes,
 * byte-slice, aux-load-bytes, constant-load, state-to-bytes, bytes-to-state)
 * + the existing `generic.state-to-aux@1` bridge — no more
 * SHA-256-specific helper steps in the spec.
 *
 * **Topology overview (Slice 2.6d, user picks 2026-05-25):**
 *
 * ```
 * 1.  state-to-bytes "plaintext-source"   → output = plaintext bytes
 * 2.  pad-with-byte "pad"                  → output = padded bytes
 *                                            (msg + 0x80 + zeros to ≡ 56 mod 64)
 * 3.  append-be64-length "length-append"   → output = 64-byte padded block
 *                                            (single-block "abc")
 * 4.  bytes-to-state "seed-schedule"       → state = padded block (64 bytes)
 * 5.  for-each-subgraph-with-history "msg-schedule" → state = W (256 bytes)
 *       body (14 leaves per iteration): aux-load-bytes ×4 (prior-2/-7/-15/-16)
 *                                       + σ1 chain (2 ROTR + 1 SHR + 1 XOR)
 *                                       + σ0 chain (2 ROTR + 1 SHR + 1 XOR)
 *                                       + 4-way add-mod-32 (W_t)
 *                                       + bytes-to-state (FES body exit)
 *       iterationCount=48, lookbackOffsets=[2,7,15,16], entryLen=4
 * 6.  state-to-aux "W-publish"             → aux["W"] = W (256 bytes)
 *                                            [Q1 = (b): W lives in aux from
 *                                            here on, not in state]
 * 7.  aux-load "K-to-aux"                  → aux["K"] = K_0..K_63 (256 bytes)
 * 8.  aux-load "H-to-aux"                  → aux["H"] = H_0..H_7 (32 bytes,
 *                                            used by final-add)
 * 9.  constant-load "H-constant"           → output = H_0..H_7 (32 bytes)
 * 10. bytes-to-state "init-working-vars"   → state = working_vars (32 bytes)
 * 11. (× 64) group "round.t":              28 leaves per round
 *       state-to-bytes → split-bytes(×8 widths=4)
 *       aux-load-bytes K + byte-slice K_t
 *       aux-load-bytes W + byte-slice W_t
 *       Σ1(e): 3 × rotate-bits-right(2,11,25) + xor 3-way
 *       Σ0(a): 3 × rotate-bits-right(6,13,22) + xor 3-way   [the constants
 *         look swapped vs. the prose — see math comments below: lowercase
 *         is Σ0(a)=ROTR2⊕ROTR13⊕ROTR22; uppercase Σ1(e)=ROTR6⊕ROTR11⊕ROTR25.
 *         Per FIPS 180-4 §4.1.2]
 *       Ch(e,f,g): not(e) + and(e,f) + and(¬e,g) + xor 2-way
 *       Maj(a,b,c): and(a,b) + and(a,c) + and(b,c) + xor 3-way
 *       T1 = h + Σ1(e) + Ch(e,f,g) + K_t + W_t (5-way add-mod-32)
 *       T2 = Σ0(a) + Maj(a,b,c) (2-way add-mod-32)
 *       new_a = T1 + T2 (2-way add-mod-32)
 *       new_e = d + T1 (2-way add-mod-32)
 *       Repack: concat 8-way(new_a, a, b, c, new_e, e, f, g)
 *                                  → bytes-to-state (32 bytes)
 *
 *       Renames are FREE: the next round's `a..h` are this round's
 *       (new_a, a, b, c, new_e, e, f, g) — i.e., the working variables
 *       cascade DOWN one slot, with new_a entering at position 0 and h
 *       falling off the end. This is what the 8-way concat encodes.
 * 12. final-add (13 leaves):
 *       state-to-bytes → split-bytes(×8) → a..h
 *       aux-load-bytes "fetch-H" → split-bytes(×8) → H_0..H_7
 *       × 8 add-mod-32 2-way: s_i = a_i + H_i
 *       concat 8-way → 32-byte hash
 *       bytes-to-state (final cipher state)
 * ```
 *
 * **Single-block scope.** This spec assumes the message fits in ONE
 * 64-byte block (after padding + length-suffix). The "abc" KAT (FIPS
 * 180-4 §A.1) is the canonical reference for single-block. Multi-block
 * support (per-block outer loop, running hash threaded across blocks)
 * is deferred to Slice 2.11's KAT matrix.
 *
 * **Math byte-identical to FIPS 180-4.** The "abc" KAT continues to pass
 * after the rewrite — the decomposition is algebraically identical to
 * the helpers it replaces. `tests/sha-256.test.ts` is the load-bearing
 * safety net for this; the decomposition-parity test in
 * `tests/sha-256-decomposition-parity.test.ts` (Slice 2.6d step 5) adds
 * frame-level structural assertions on top.
 *
 * **Frame count grows substantially.** From 123 frames per run (2.6b's
 * coarse helpers) to ~2486 per run (decomposed). Every algorithmic
 * sub-step is now individually visible in the trace, with provenance
 * traceable through each port-native primitive's contract. Pedagogy
 * payoff: the math IS the cipher — students see every ROTR, every XOR,
 * every modular add making up Σ0/Σ1/Ch/Maj/T1/T2.
 *
 * **References:**
 *   - FIPS 180-4 §5.1.1 — Preprocessing (padding + length suffix)
 *   - FIPS 180-4 §5.3.3 — Initial hash values H_0..H_7
 *   - FIPS 180-4 §4.2.2 — Round constants K_0..K_63
 *   - FIPS 180-4 §4.1.2 — Σ0/Σ1/σ0/σ1/Ch/Maj definitions
 *   - FIPS 180-4 §6.2.2 — Single-block message hash computation
 *   - FIPS 180-4 §A.1   — KAT for the 3-byte message "abc"
 *   - docs/plans/universal-port-phase-2-slices.md (Slice 2.6c design +
 *     Slice 2.6d implementation)
 */

import type { CipherSpec, StepDocumentation, StepNode } from "../core/types";

// ─── SHA-256 constants (FIPS 180-4 §4.2.2 + §5.3.3) ───────────────────────

/**
 * SHA-256 round constants K_0..K_63 — first 32 bits of the fractional
 * parts of the cube roots of the first 64 primes (per FIPS 180-4 §4.2.2).
 * Loaded into `aux["K"]` once at the start of the cipher via
 * `generic.aux-load@1`; each compression round reads its K_t slice from
 * offset `4*t` within aux["K"].
 */
const SHA256_K_WORDS: readonly number[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/**
 * SHA-256 initial hash values H_0..H_7 — first 32 bits of the fractional
 * parts of the square roots of the first 8 primes (per FIPS 180-4 §5.3.3).
 * Used twice: (1) to seed the working variables before compression
 * (constant-load → bytes-to-state), (2) as the per-word addend in the
 * final-add step (aux["H"], read via aux-load-bytes + split-bytes).
 */
const SHA256_H_WORDS: readonly number[] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const wordsToBytes = (words: readonly number[]): number[] => {
  const out = new Array<number>(words.length * 4);
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as number;
    out[i * 4 + 0] = (w >>> 24) & 0xff;
    out[i * 4 + 1] = (w >>> 16) & 0xff;
    out[i * 4 + 2] = (w >>> 8) & 0xff;
    out[i * 4 + 3] = w & 0xff;
  }
  return out;
};

const SHA256_K_BYTES = wordsToBytes(SHA256_K_WORDS); // 256 bytes
const SHA256_H_BYTES = wordsToBytes(SHA256_H_WORDS); // 32 bytes

// ─── narrationOverride: SHA-256-specific prose for every spec leaf ────────
//
// Slice 2.8 of the universal-port-dataflow plan (2026-05-25). Each spec
// leaf carries a `StepDocumentation` override that names what THIS leaf
// does inside SHA-256, instead of the registry's generic doc for the
// underlying port-native primitive. The registry doc remains the
// fallback for palette-dropped primitives that haven't been authored
// into a cipher-specific role.
//
// **Reference-sharing is intentional and safe.** Every leaf in a given
// role shares the SAME override object (e.g., all 64 compression rounds'
// `Sigma1` leaves point at `NARR_ROUND_SIGMA1`). `narrationOverride` is
// read-only — the runtime never mutates it, and `core/spec-mutations.ts`
// rebuilds the tree rather than mutating in place. Unlike `params`
// (where shared references cause silent cross-leaf edits — see the
// `Sharing param objects across CipherSpec leaves` pitfall in
// `src/steps/CLAUDE.md`), the override has no editor and no mutation
// path.
//
// **References.** Every override carries at least one FIPS 180-4
// citation pointing at the section that justifies its role.

// ── Preprocessing (4 leaves) ──────────────────────────────────────────────

const NARR_PLAINTEXT_SOURCE: StepDocumentation = {
  name: "Plaintext source",
  summary: "Expose the input message bytes on a port so the padding step can read them.",
  detail: `Reads the cipher's input state (the bytes of the message
to be hashed) and emits them on port \`output\`. This is the entry
point — every downstream step that needs the original message reads
from here (notably the padding step AND the length-suffix step, which
encodes the **original** message length, not the padded length).`,
  references: ["FIPS 180-4 §5.1.1 — Preprocessing overview"],
};

const NARR_PAD: StepDocumentation = {
  name: "Pad with 0x80 + zeros (FIPS 180-4 §5.1.1)",
  summary:
    "Append 0x80 then zeros until length ≡ 56 (mod 64), reserving 8 bytes for the length suffix.",
  detail: `SHA-256 padding rule for single-block messages (≤ 55 bytes):
append the byte \`0x80\` (= bits \`10000000\`), then append zero bytes
until the running length is congruent to 56 modulo 64. The trailing 8
bytes of the final 64-byte block are reserved for the big-endian
64-bit length suffix appended in the next step.

Why the \`0x80\` sentinel: FIPS 180-4 §5.1.1 specifies "append a single
1 bit" followed by "the minimum number of 0 bits, so that the resulting
length is congruent to 448 mod 512." On byte-aligned messages, "a 1 bit
plus seven 0 bits" is the byte \`0x80\`.`,
  references: ["FIPS 180-4 §5.1.1 — Padding the message"],
};

const NARR_LENGTH_APPEND: StepDocumentation = {
  name: "Append BE-64 length of original message (FIPS 180-4 §5.1.1)",
  summary:
    "Suffix the padded message with the original message length in bits, big-endian, 64 bits.",
  detail: `The final 8 bytes of SHA-256's input block encode \`L\` —
the **original** (pre-padding) message length, in bits, as a 64-bit
big-endian unsigned integer. For the "abc" KAT (FIPS 180-4 §A.1) this
is \`0x0000000000000018\` (= 24 bits). After this step the input is
exactly 64 bytes (single-block scope of this spec).

The length-source port wires back to \`plaintext-source\` — the
original message — NOT to the padded bytes, because the length encoded
here is the original length per the FIPS specification.`,
  references: ["FIPS 180-4 §5.1.1 — Length suffix"],
};

const NARR_SEED_SCHEDULE: StepDocumentation = {
  name: "Seed message schedule (bytes → state)",
  summary:
    "Bridge: copy the padded 64-byte block into state so the FES-with-history can seed its history.",
  detail: `The for-each-subgraph-with-history primitive seeds its
lookback history from parent-scope state. This bridge copies the
64-byte padded block (output of \`length-append\`) into state.bytes
so the FES seeding logic can populate \`prior-1\` through \`prior-16\`
with the message words \`M_0..M_15\` before the first iteration runs.`,
  references: ["FIPS 180-4 §6.2.2 — Message schedule preparation"],
};

// ── Schedule body (14 leaves, shared across 48 FES iterations) ────────────

const NARR_SCHED_FETCH_P2: StepDocumentation = {
  name: "Fetch W_{t-2}",
  summary: "Load the message-schedule word from 2 iterations ago (for σ1).",
  detail: `Loads \`W_{t-2}\` — the schedule word produced two iterations
back — via \`aux["prior-2"]\`. This is one of two inputs the \`σ1\`
mixing helper will operate on inside this iteration body.

How the lookback works mechanically: the FES-with-history primitive
maintains a sliding window of the most recent \`lookbackOffsets\`
outputs as \`aux["prior-N"]\` entries. For the SHA-256 schedule the
container declares \`lookbackOffsets: [2, 7, 15, 16]\`, so at every
iteration the runtime auto-publishes \`prior-2\`, \`prior-7\`,
\`prior-15\`, and \`prior-16\`. No explicit "store the last 16 words"
plumbing is needed in the spec.

Seeding: for early iterations where the lookback would reach BEFORE
iteration 0, the FES seeds the history from the parent-scope state.
For SHA-256 that means \`W_0..W_15\` (the first 16 schedule words)
come directly from the padded message block, then iterations 16..63
extend the schedule via the σ1+σ0 recurrence.

Role in the larger recurrence: feeds the \`σ1\` chain (3 rotations
+ 1 shift + XOR + addition into \`W_t\`).`,
  references: ["FIPS 180-4 §6.2.2 — W_t recurrence", "FIPS 180-4 §6.2.2 — Message schedule"],
};

const NARR_SCHED_FETCH_P7: StepDocumentation = {
  name: "Fetch W_{t-7}",
  summary: "Load the message-schedule word from 7 iterations ago (additive term).",
  detail: `Additive term in the W_t recurrence: \`W_t = σ1(W_{t-2}) +
W_{t-7} + σ0(W_{t-15}) + W_{t-16}\`. The FES-with-history runtime
auto-publishes \`aux["prior-7"]\`.`,
  references: ["FIPS 180-4 §6.2.2 — W_t recurrence"],
};

const NARR_SCHED_FETCH_P15: StepDocumentation = {
  name: "Fetch W_{t-15}",
  summary: "Load the message-schedule word from 15 iterations ago (for σ0).",
  detail: `\`σ0\` of the W_t recurrence operates on \`W_{t-15}\`. The
FES-with-history runtime auto-publishes \`aux["prior-15"]\`.`,
  references: ["FIPS 180-4 §6.2.2 — W_t recurrence"],
};

const NARR_SCHED_FETCH_P16: StepDocumentation = {
  name: "Fetch W_{t-16}",
  summary: "Load the message-schedule word from 16 iterations ago (additive term).",
  detail: `Last additive term in the W_t recurrence: ties the new
schedule word back to the message word from 16 positions earlier
(which, for early iterations, is one of the seeded \`M_0..M_15\`
message words).`,
  references: ["FIPS 180-4 §6.2.2 — W_t recurrence"],
};

const NARR_SCHED_SIGMA1_R17: StepDocumentation = {
  name: "σ1: ROTR¹⁷(W_{t-2})",
  summary: "First rotation of the lowercase-sigma-1 helper: rotate W_{t-2} right by 17 bits.",
  detail: `One of three rotations that make up \`σ1\`:

\`\`\`
σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
\`\`\`

(FIPS 180-4 §4.1.2 equation 4.7). This leaf computes the
\`ROTR¹⁷\` term. The XOR of all three terms lands in \`sigma1\`.`,
  references: ["FIPS 180-4 §4.1.2 — σ1 definition"],
};

const NARR_SCHED_SIGMA1_R19: StepDocumentation = {
  name: "σ1: ROTR¹⁹(W_{t-2})",
  summary: "Second rotation of σ1: rotate W_{t-2} right by 19 bits.",
  detail: `Middle term of \`σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)\`
(FIPS 180-4 §4.1.2 eq. 4.7).

Where bits go: ROTR¹⁹ sends input bit n to output position
(n − 19) mod 32. Concretely, input bits 31..19 land at output
positions 12..0; input bits 18..0 wrap to positions 31..13.

XOR'd with \`ROTR¹⁷(W_{t-2})\` and \`SHR¹⁰(W_{t-2})\` in \`σ1(W_{t-2})\`.`,
  references: ["FIPS 180-4 §4.1.2 — σ1 definition"],
};

const NARR_SCHED_SIGMA1_S10: StepDocumentation = {
  name: "σ1: SHR¹⁰(W_{t-2})",
  summary: "Logical right SHIFT of W_{t-2} by 10 bits (zeros enter the top).",
  detail: `The third term of \`σ1\` is a **shift**, not a rotation —
the bits shifted off the right disappear and zeros enter from the top.
This is why \`σ1\` (lowercase) is distinct from \`Σ1\` (uppercase,
which is pure rotations); they appear together in SHA-256 but compute
different transforms.`,
  references: ["FIPS 180-4 §4.1.2 — σ1 definition"],
};

const NARR_SCHED_SIGMA1: StepDocumentation = {
  name: "σ1(W_{t-2}) = ROTR¹⁷ ⊕ ROTR¹⁹ ⊕ SHR¹⁰",
  summary: "XOR-combine the three σ1 components into the schedule's σ1 contribution.",
  detail: `Per FIPS 180-4 §4.1.2 eq. 4.7:

\`\`\`
σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
\`\`\`

What it does cryptographically: \`σ1\` is one of two **mixing helpers**
in the message schedule. By XORing three different bit-displaced views
of \`W_{t-2}\`, it spreads each input bit across many output positions,
so the recurrence can't be inverted just by undoing additions. The
asymmetric mix of two rotations PLUS a logical shift (the \`SHR¹⁰\`,
which loses high bits to zero) deliberately breaks rotational symmetry —
without it, the schedule could be transposed bit-cyclically and still
satisfy the recurrence.

Role in the larger recurrence: this is the first of four addends in

\`\`\`
W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}   (mod 2³²)
\`\`\`

Runs once per FES iteration (t = 16..63) — 48 evaluations per single-block hash.`,
  references: ["FIPS 180-4 §4.1.2 — σ1 definition", "FIPS 180-4 §6.2.2 — W_t recurrence"],
};

const NARR_SCHED_SIGMA0_R7: StepDocumentation = {
  name: "σ0: ROTR⁷(W_{t-15})",
  summary: "First rotation of σ0: rotate W_{t-15} right by 7 bits.",
  detail: `One of three rotations that make up \`σ0\`:

\`\`\`
σ0(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
\`\`\`

(FIPS 180-4 §4.1.2 eq. 4.6). Note the rotation constants are
**different** from σ1's (7/18/3 vs. 17/19/10).`,
  references: ["FIPS 180-4 §4.1.2 — σ0 definition"],
};

const NARR_SCHED_SIGMA0_R18: StepDocumentation = {
  name: "σ0: ROTR¹⁸(W_{t-15})",
  summary: "Second rotation of σ0: rotate W_{t-15} right by 18 bits.",
  detail: `Middle term of \`σ0(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)\`
(FIPS 180-4 §4.1.2 eq. 4.6).

Where bits go: ROTR¹⁸ sends input bit n to output position
(n − 18) mod 32. Concretely, input bits 31..18 land at output
positions 13..0; input bits 17..0 wrap to positions 31..14.

XOR'd with \`ROTR⁷(W_{t-15})\` and \`SHR³(W_{t-15})\` in \`σ0(W_{t-15})\`.`,
  references: ["FIPS 180-4 §4.1.2 — σ0 definition"],
};

const NARR_SCHED_SIGMA0_S3: StepDocumentation = {
  name: "σ0: SHR³(W_{t-15})",
  summary: "Logical right SHIFT of W_{t-15} by 3 bits (zeros enter the top).",
  detail: `Third term of \`σ0\` is a SHIFT (not a rotation) — bits
shifted off the right disappear and zeros enter from the top.`,
  references: ["FIPS 180-4 §4.1.2 — σ0 definition"],
};

const NARR_SCHED_SIGMA0: StepDocumentation = {
  name: "σ0(W_{t-15}) = ROTR⁷ ⊕ ROTR¹⁸ ⊕ SHR³",
  summary: "XOR-combine the three σ0 components into the schedule's σ0 contribution.",
  detail: `Per FIPS 180-4 §4.1.2 eq. 4.6:

\`\`\`
σ0(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
\`\`\`

What it does cryptographically: \`σ0\` is the schedule's second
mixing helper (sibling of \`σ1\`). Same shape — two rotations XOR'd
with one logical shift — but DIFFERENT constants (7/18/3 vs σ1's
17/19/10). The constant pair was chosen so that \`σ0\` and \`σ1\` together
diffuse bits across the full 32-bit word: any single input bit of
\`W_{t-2}\` or \`W_{t-15}\` ends up influencing many bits of the new
\`W_t\`. Pairing two different mixers (rather than one) and applying
them to two different lookback positions is what gives the message
schedule its avalanche property.

Role in the larger recurrence: this is the third of four addends in

\`\`\`
W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}   (mod 2³²)
\`\`\`

The \`W_{t-15}\` argument is what couples the new word to a different
lookback distance than σ1's — so the two mixers don't collapse into a
single combined helper.`,
  references: ["FIPS 180-4 §4.1.2 — σ0 definition", "FIPS 180-4 §6.2.2 — W_t recurrence"],
};

const NARR_SCHED_W_T: StepDocumentation = {
  name: "W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}",
  summary:
    "Combine the four schedule terms via 4-way addition mod 2³² to produce the next schedule word.",
  detail: `The message-schedule recurrence from FIPS 180-4 §6.2.2:

\`\`\`
W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}   (mod 2³²)
\`\`\`

Runs 48 times (for t = 16..63) under the for-each-subgraph-with-history
primitive; the first 16 schedule words (W_0..W_15) come directly from
the padded message block via the FES seeding contract.`,
  references: ["FIPS 180-4 §6.2.2 — Step 1, message schedule"],
};

const NARR_SCHED_OUT: StepDocumentation = {
  name: "Schedule iteration exit (bytes → state)",
  summary: "Bridge: write the new W_t word into state.bytes as the FES iteration's 4-byte output.",
  detail: `The FES-with-history primitive validates that each
iteration body exits with exactly \`historyEntryByteLength\` bytes in
state (here, 4 bytes — one 32-bit word). This bridge moves the W_t
word from its port into state, completing the iteration's contract.

After all 48 iterations, state holds the concatenated 256-byte W
buffer (W_0..W_63), ready to be published to aux for the compression
rounds.`,
  references: ["FIPS 180-4 §6.2.2 — Step 1"],
};

// ── Aux setup + working-variable init (5 leaves) ──────────────────────────

const NARR_W_PUBLISH: StepDocumentation = {
  name: "Publish W to aux",
  summary: 'Snapshot the 256-byte W schedule into aux["W"] so each round can read its W_t slice.',
  detail: `After the FES exits, state holds the full 256-byte W
buffer. The 64 compression rounds each need to read their own W_t
slice — but state is about to be overwritten with the working
variables, so we snapshot W into aux first. Each round then loads
aux["W"] and slices out 4 bytes at offset \`4*t\`.

This is the Q1 = (b) "W in aux" decision (Slice 2.6d pre-slice user
pick): W lives in aux from here on, NOT in state.`,
  references: ["FIPS 180-4 §6.2.2 — Step 2 (working variables init)"],
};

const NARR_K_TO_AUX: StepDocumentation = {
  name: "Load K_0..K_63 to aux",
  summary: 'Bake the 64 SHA-256 round constants into aux["K"] as a 256-byte buffer.',
  detail: `Publishes the 64 SHA-256 round constants \`K_0..K_63\` into
\`aux["K"]\` as a single 256-byte buffer (K_0 at offset 0, K_63 at
offset 252) so each compression round can fetch + slice its own K_t
in two cheap steps.

Provenance of the constants: per FIPS 180-4 §4.2.2, each \`K_t\` is
the first 32 bits of the FRACTIONAL part of the cube root of the
\`(t+1)\`-th prime. So \`K_0\` derives from cbrt(2), \`K_1\` from
cbrt(3), and so on through cbrt(311) for \`K_63\`. These are called
"nothing-up-my-sleeve" constants: a fixed, mechanical derivation that
anyone can reproduce, so no hidden trapdoor can be smuggled in via the
round-constant choice. The same provenance rule is used by SHA-1
(square roots of small primes) and SHA-512 (cube roots, 64-bit
truncations of the first 80 primes).

Role in the larger recurrence: each round t reads K_t from this
buffer and uses it as the round constant in T1's 5-way addition.`,
  references: ["FIPS 180-4 §4.2.2 — K_0..K_63", "Wikipedia — Nothing-up-my-sleeve number"],
};

const NARR_H_TO_AUX: StepDocumentation = {
  name: "Load H_0..H_7 to aux",
  summary: 'Bake the 8 SHA-256 initial-hash-value words into aux["H"] as a 32-byte buffer.',
  detail: `Publishes the 8 SHA-256 initial-hash-value words
\`H_0..H_7\` into \`aux["H"]\` as a 32-byte buffer (H_0 at offset 0,
H_7 at offset 28) for the final-add step to read.

Provenance of the constants: per FIPS 180-4 §5.3.3, each \`H_i\` is
the first 32 bits of the FRACTIONAL part of the SQUARE root of the
\`(i+1)\`-th prime — so \`H_0 = sqrt(2)\` truncated, \`H_1 = sqrt(3)\`,
through \`H_7 = sqrt(19)\`. Same "nothing-up-my-sleeve" rationale as
the round constants \`K_t\` (which use cube roots): a mechanical,
reproducible derivation that prevents trapdoors hidden in arbitrary
constant choices.

Why two copies of H — one in aux here, one as a port-source at
\`H-constant\` next: the two uses are structurally different.
\`H-constant\` feeds the WORKING-VARIABLE INIT (state ← H_0..H_7
before round 0); \`aux["H"]\` feeds the FINAL ADD (digest[i] = H_i +
a_i after round 63). Keeping them as separate spec leaves makes the
two roles visible in the trace instead of conflating them into one
constant pool.`,
  references: [
    "FIPS 180-4 §5.3.3 — Initial hash values",
    "Wikipedia — Nothing-up-my-sleeve number",
  ],
};

const NARR_H_CONSTANT: StepDocumentation = {
  name: "Constant load H_0..H_7",
  summary: "Emit the 8 initial-hash-value words on a port to seed the working variables.",
  detail: `Same H_0..H_7 constants as the aux-loaded copy, but
emitted on a port for use by the next bridge (\`init-working-vars\`),
which writes them into state.bytes as the initial values of the 8
working variables (a, b, c, d, e, f, g, h) before round 0.`,
  references: ["FIPS 180-4 §5.3.3 — Initial hash values H_0..H_7"],
};

const NARR_INIT_WORKING_VARS: StepDocumentation = {
  name: "Seed working variables (a..h ← H_0..H_7)",
  summary:
    "Bridge: copy H_0..H_7 into state.bytes as the initial 8 working variables before round 0.",
  detail: `Initializes the 8 32-bit working variables a, b, c, d, e,
f, g, h to H_0..H_7 respectively (FIPS 180-4 §6.2.2 Step 2). State
becomes a 32-byte buffer; rounds 0..63 will repeatedly read this
state, transform it, and write it back.`,
  references: ["FIPS 180-4 §6.2.2 — Step 2 (working variables init)"],
};

// ── Compression round body (28 leaves, shared by reference across 64 rounds) ─

const NARR_ROUND_STATE_IN: StepDocumentation = {
  name: "Round entry: state → bytes",
  summary: "Expose the 32-byte working-variable state on a port so the round body can split it.",
  detail: `Bridge from state to bytes. The 32 bytes are the 8 working
variables a, b, c, d, e, f, g, h (each 4 bytes, big-endian).`,
  references: ["FIPS 180-4 §6.2.2 — Step 3"],
};

const NARR_ROUND_SPLIT: StepDocumentation = {
  name: "Split into a, b, c, d, e, f, g, h",
  summary: "Split the 32-byte working-variable buffer into 8 separate 4-byte words.",
  detail: `Output port \`output0\` carries \`a\`, \`output1\` carries
\`b\`, ..., \`output7\` carries \`h\`. The round body reads each of
these ports as needed for the round's various subterms (Σ0(a),
Σ1(e), Ch(e,f,g), Maj(a,b,c), and the new_a/new_e formulas).`,
  references: ["FIPS 180-4 §6.2.2 — Step 3 (working variable assignment)"],
};

const NARR_ROUND_FETCH_K: StepDocumentation = {
  name: "Fetch K array from aux",
  summary: 'Load the 256-byte aux["K"] buffer of round constants for this round\'s K_t slice.',
  detail: `Loads the full 256-byte K buffer (the 64 round constants
K_0..K_63, baked at \`K-to-aux\` once per spec run) into a port. The
next leaf slices out the 4-byte K_t word for THIS round.

Why fetch the whole buffer then slice: under the universal port-native
model, every leaf operates on bytes flowing through ports — there's no
"random index into aux" primitive. Fetching + slicing keeps the cipher
expressible from a small primitive vocabulary at the cost of one extra
visible step per round.`,
  references: ["FIPS 180-4 §4.2.2 — K_t"],
};

const NARR_ROUND_K_T: StepDocumentation = {
  name: "K_t: slice round t's constant",
  summary: 'Extract the 4-byte K_t round constant at offset 4·t within aux["K"].',
  detail: `Selects \`K_t\` (the round constant for THIS round) from the
shared 256-byte K buffer:

\`\`\`
K_t = aux["K"][4*t .. 4*t+4]
\`\`\`

Different round groups use different \`offset\` params (\`4 * t\`) —
this is the only round-specific parameter (besides W_t's identical
offset). Per FIPS 180-4 §4.2.2, each \`K_t\` is the first 32 bits of
the fractional part of the cube root of the t-th prime, ensuring the
constants are "nothing-up-my-sleeve" — derivable from a mathematical
process anyone can replicate, so no hidden trapdoor can be smuggled
through round-constant choice.

Role in the larger recurrence: contributes to T1:

\`\`\`
T1 = h + Σ1(e) + Ch(e, f, g) + K_t + W_t   (mod 2³²)
\`\`\`

Different per round (so each round runs a "different function"),
ensuring identical-input rounds don't produce identical outputs.`,
  references: ["FIPS 180-4 §4.2.2 — K_t", "FIPS 180-4 §6.2.2 — Step 3 (T1)"],
};

const NARR_ROUND_FETCH_W: StepDocumentation = {
  name: "Fetch W schedule from aux",
  summary: 'Load the 256-byte aux["W"] message-schedule buffer for this round\'s W_t slice.',
  detail: `Loads the full 256-byte W buffer (published by the
schedule's \`W-publish\` leaf at the top of the cipher) into a port.
The next leaf slices out \`W_t\` for this round.

Note that W changes with every input message — unlike K which is fixed.
That's WHY the schedule exists: to expand the 16-word message block
into 64 distinct round inputs, one per round, all derived from the
input via the σ0/σ1 recurrence.`,
  references: ["FIPS 180-4 §6.2.2 — Step 1"],
};

const NARR_ROUND_W_T: StepDocumentation = {
  name: "W_t: slice round t's message-schedule word",
  summary: 'Extract the 4-byte W_t schedule word at offset 4·t within aux["W"].',
  detail: `Selects \`W_t\` (this round's message-schedule contribution)
from the shared 256-byte W buffer:

\`\`\`
W_t = aux["W"][4*t .. 4*t+4]
\`\`\`

Role in the larger recurrence: paired with \`K_t\` as one of the five
T1 addends:

\`\`\`
T1 = h + Σ1(e) + Ch(e, f, g) + K_t + W_t   (mod 2³²)
\`\`\`

The pair \`(K_t, W_t)\` together gives each round its identity: \`K_t\`
varies BY round (fixed across messages), \`W_t\` varies BY message
(fixed across hashes of the same message). Their sum injects both
fresh round-key material AND message material into T1 every round.`,
  references: ["FIPS 180-4 §6.2.2 — Step 1 / W_t", "FIPS 180-4 §6.2.2 — Step 3 (T1)"],
};

const NARR_ROUND_SIGMA1_R6: StepDocumentation = {
  name: "Σ1: ROTR⁶(e)",
  summary: "First rotation of the uppercase-Sigma-1 helper: rotate e right by 6 bits.",
  detail: `One of three rotations that make up \`Σ1\`:

\`\`\`
Σ1(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
\`\`\`

(FIPS 180-4 §4.1.2 eq. 4.5). Σ1 (capital) uses ROTRs only — no
SHRs, distinguishing it from σ1 (lowercase) used by the schedule.`,
  references: ["FIPS 180-4 §4.1.2 — Σ1 definition"],
};

const NARR_ROUND_SIGMA1_R11: StepDocumentation = {
  name: "Σ1: ROTR¹¹(e)",
  summary: "Second rotation of Σ1: rotate e right by 11 bits.",
  detail: `Middle term of \`Σ1(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)\`
(FIPS 180-4 §4.1.2 eq. 4.5).

Where bits go: ROTR¹¹ sends input bit n to output position
(n − 11) mod 32. Concretely, input bits 31..11 land at output
positions 20..0; input bits 10..0 wrap to positions 31..21.

XOR'd with \`ROTR⁶(e)\` and \`ROTR²⁵(e)\` in \`Σ1(e)\`.`,
  references: ["FIPS 180-4 §4.1.2 — Σ1 definition"],
};

const NARR_ROUND_SIGMA1_R25: StepDocumentation = {
  name: "Σ1: ROTR²⁵(e)",
  summary: "Third rotation of Σ1: rotate e right by 25 bits.",
  detail: `Last term of \`Σ1(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)\`
(FIPS 180-4 §4.1.2 eq. 4.5).

Where bits go: ROTR²⁵ sends input bit n to output position
(n − 25) mod 32. Concretely, input bits 31..25 land at output
positions 6..0; input bits 24..0 wrap to positions 31..7.

XOR'd with \`ROTR⁶(e)\` and \`ROTR¹¹(e)\` in \`Σ1(e)\`.`,
  references: ["FIPS 180-4 §4.1.2 — Σ1 definition"],
};

const NARR_ROUND_SIGMA1: StepDocumentation = {
  name: "Σ1(e) = ROTR⁶(e) ⊕ ROTR¹¹(e) ⊕ ROTR²⁵(e)",
  summary: "XOR-combine the three Σ1 rotations into one of T1's addends.",
  detail: `Per FIPS 180-4 §4.1.2 eq. 4.5:

\`\`\`
Σ1(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
\`\`\`

What it does cryptographically: \`Σ1\` is the **diffusion helper for
\`e\`** inside the compression round. Three different rotations XOR'd
together so that every bit of \`e\` influences many bits of the output
— this is what couples T1 to the high-bit positions of \`e\` and
prevents trivial linear shortcuts through the round.

Why pure rotations (no SHR): \`Σ1\` (uppercase) operates on a single
32-bit working variable that we WANT preserved through the round; a
SHR would lose information. By contrast, the schedule's lowercase
\`σ1\` includes an SHR because it's mixing into the *recurrence*, not
into a feedback path.

Role in the larger recurrence: this is one of the five addends in

\`\`\`
T1 = h + Σ1(e) + Ch(e, f, g) + K_t + W_t   (mod 2³²)
\`\`\`

T1 then feeds both \`new_a\` (= T1 + T2) and \`new_e\` (= d + T1) —
so \`Σ1(e)\` reaches BOTH outputs of the round, not just one.`,
  references: ["FIPS 180-4 §4.1.2 — Σ1 definition", "FIPS 180-4 §6.2.2 — Step 3 (T1)"],
};

const NARR_ROUND_SIGMA0_R2: StepDocumentation = {
  name: "Σ0: ROTR²(a)",
  summary: "First rotation of the uppercase-Sigma-0 helper: rotate a right by 2 bits.",
  detail: `One of three rotations that make up \`Σ0\`:

\`\`\`
Σ0(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
\`\`\`

(FIPS 180-4 §4.1.2 eq. 4.4). Σ0 (capital) uses ROTRs only — no
SHRs, distinguishing it from σ0 (lowercase) used by the schedule.
Note Σ0's constants (2/13/22) are DIFFERENT from Σ1's (6/11/25).`,
  references: ["FIPS 180-4 §4.1.2 — Σ0 definition"],
};

const NARR_ROUND_SIGMA0_R13: StepDocumentation = {
  name: "Σ0: ROTR¹³(a)",
  summary: "Second rotation of Σ0: rotate a right by 13 bits.",
  detail: `Middle term of \`Σ0(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)\`
(FIPS 180-4 §4.1.2 eq. 4.4).

Where bits go: ROTR¹³ sends input bit n to output position
(n − 13) mod 32. Concretely, input bits 31..13 land at output
positions 18..0; input bits 12..0 wrap to positions 31..19.

XOR'd with \`ROTR²(a)\` and \`ROTR²²(a)\` in \`Σ0(a)\`.`,
  references: ["FIPS 180-4 §4.1.2 — Σ0 definition"],
};

const NARR_ROUND_SIGMA0_R22: StepDocumentation = {
  name: "Σ0: ROTR²²(a)",
  summary: "Third rotation of Σ0: rotate a right by 22 bits.",
  detail: `Last term of \`Σ0(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)\`
(FIPS 180-4 §4.1.2 eq. 4.4).

Where bits go: ROTR²² sends input bit n to output position
(n − 22) mod 32. Concretely, input bits 31..22 land at output
positions 9..0; input bits 21..0 wrap to positions 31..10.

XOR'd with \`ROTR²(a)\` and \`ROTR¹³(a)\` in \`Σ0(a)\`.`,
  references: ["FIPS 180-4 §4.1.2 — Σ0 definition"],
};

const NARR_ROUND_SIGMA0: StepDocumentation = {
  name: "Σ0(a) = ROTR²(a) ⊕ ROTR¹³(a) ⊕ ROTR²²(a)",
  summary: "XOR-combine the three Σ0 rotations into one of T2's addends.",
  detail: `Per FIPS 180-4 §4.1.2 eq. 4.4:

\`\`\`
Σ0(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
\`\`\`

What it does cryptographically: \`Σ0\` is the **diffusion helper for
\`a\`** (sibling of \`Σ1\`, which diffuses \`e\`). Pure rotations only —
no SHR — so it preserves all 32 bits of \`a\` while spreading each
input bit across the output. The constant pair (2/13/22) is
intentionally different from \`Σ1\`'s (6/11/25); using two distinct
mixers prevents the round body from collapsing into a single weaker
function.

Role in the larger recurrence: this is one of two addends in

\`\`\`
T2 = Σ0(a) + Maj(a, b, c)   (mod 2³²)
\`\`\`

T2 contributes ONLY to \`new_a\` (= T1 + T2), NOT to \`new_e\`. That
asymmetry between \`a\` and \`e\`'s update paths is what makes the
working-variable cascade non-trivial — \`Σ0\` is on the \`a\`-only
branch.`,
  references: ["FIPS 180-4 §4.1.2 — Σ0 definition", "FIPS 180-4 §6.2.2 — Step 3 (T2)"],
};

const NARR_ROUND_CH_NOT_E: StepDocumentation = {
  name: "Ch helper: ¬e",
  summary: "Bitwise NOT of e (computes the (¬e ∧ g) term of Ch).",
  detail: `Intermediate term in the Ch (choose) helper:

\`\`\`
Ch(e, f, g) = (e ∧ f) ⊕ (¬e ∧ g)
\`\`\`

(FIPS 180-4 §4.1.2 eq. 4.2). This leaf computes \`¬e\`; the next
leaf ANDs it with \`g\`.

Intuition: for each bit position, \`Ch\` "chooses" f or g based on
e's bit — if e's bit is 1, the result is f's bit; if e's bit is 0,
the result is g's bit.`,
  references: ["FIPS 180-4 §4.1.2 — Ch definition"],
};

const NARR_ROUND_CH_E_AND_F: StepDocumentation = {
  name: "Ch helper: e ∧ f",
  summary: "Bitwise AND of e and f.",
  detail: `Left term of \`Ch(e, f, g) = (e ∧ f) ⊕ (¬e ∧ g)\` (FIPS
180-4 §4.1.2 eq. 4.2).

Bit-level: output bit i = e_i ∧ f_i, computed in parallel across
all 32 positions. So this leaf passes through f's bits exactly
where e has a 1, and forces a 0 wherever e has a 0.

XOR'd with \`(¬e) ∧ g\` in \`Ch(e, f, g)\`.`,
  references: ["FIPS 180-4 §4.1.2 — Ch definition"],
};

const NARR_ROUND_CH_NOTE_AND_G: StepDocumentation = {
  name: "Ch helper: (¬e) ∧ g",
  summary: "Bitwise AND of (¬e) and g.",
  detail: `Right term of \`Ch(e, f, g) = (e ∧ f) ⊕ (¬e ∧ g)\` (FIPS
180-4 §4.1.2 eq. 4.2). Wires in the upstream \`Ch-not_e\` leaf's
output as the left operand.

Bit-level: output bit i = (¬e_i) ∧ g_i, computed in parallel
across all 32 positions. So this leaf passes through g's bits
exactly where e has a 0, and forces a 0 wherever e has a 1 —
the mirror image of \`e ∧ f\`.

XOR'd with \`e ∧ f\` in \`Ch(e, f, g)\`. Together the two terms
realize the bit-level conditional choose: e_i picks between
f_i and g_i.`,
  references: ["FIPS 180-4 §4.1.2 — Ch definition"],
};

const NARR_ROUND_CH: StepDocumentation = {
  name: "Ch(e, f, g) = (e ∧ f) ⊕ (¬e ∧ g)",
  summary: "XOR the two Ch terms together: one of T1's addends.",
  detail: `\`Ch\` is the bit-level conditional choose: for each bit
position, e selects between f (when e_i = 1) and g (when e_i = 0).
One of the five addends in T1 = h + Σ1(e) + Ch(e,f,g) + K_t + W_t.`,
  references: ["FIPS 180-4 §4.1.2 — Ch definition"],
};

const NARR_ROUND_MAJ_AB: StepDocumentation = {
  name: "Maj helper: a ∧ b",
  summary: "Bitwise AND of a and b.",
  detail: `First term of the Maj helper:

\`\`\`
Maj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)
\`\`\`

(FIPS 180-4 §4.1.2 eq. 4.3). Intuition: for each bit position, Maj
outputs the majority bit of a, b, c.`,
  references: ["FIPS 180-4 §4.1.2 — Maj definition"],
};

const NARR_ROUND_MAJ_AC: StepDocumentation = {
  name: "Maj helper: a ∧ c",
  summary: "Bitwise AND of a and c.",
  detail: `Middle term of \`Maj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕
(b ∧ c)\` (FIPS 180-4 §4.1.2 eq. 4.3).

Bit-level: output bit i = a_i ∧ c_i, computed in parallel across
all 32 positions. This term contributes a 1 at position i iff
BOTH a_i and c_i are 1, regardless of b_i.

XOR'd with \`a ∧ b\` and \`b ∧ c\` in \`Maj(a, b, c)\`.`,
  references: ["FIPS 180-4 §4.1.2 — Maj definition"],
};

const NARR_ROUND_MAJ_BC: StepDocumentation = {
  name: "Maj helper: b ∧ c",
  summary: "Bitwise AND of b and c.",
  detail: `Last term of \`Maj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕
(b ∧ c)\` (FIPS 180-4 §4.1.2 eq. 4.3).

Bit-level: output bit i = b_i ∧ c_i, computed in parallel across
all 32 positions. This is the only Maj term that doesn't involve
\`a\` — together with \`a ∧ b\` and \`a ∧ c\`, the three pairwise
ANDs cover all three two-of-three combinations, which is what
makes the XOR of all three compute the majority bit.

XOR'd with \`a ∧ b\` and \`a ∧ c\` in \`Maj(a, b, c)\`.`,
  references: ["FIPS 180-4 §4.1.2 — Maj definition"],
};

const NARR_ROUND_MAJ: StepDocumentation = {
  name: "Maj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)",
  summary: "XOR the three Maj pairwise-ANDs: one of T2's addends.",
  detail: `Per FIPS 180-4 §4.1.2 eq. 4.3:

\`\`\`
Maj(a, b, c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c)
\`\`\`

What it does cryptographically: \`Maj\` is the bit-level **majority**
function — for each bit position, the output bit equals the majority
of the three input bits at that position (1 if two or three of
\`a_i, b_i, c_i\` are 1; otherwise 0). The XOR of three pairwise ANDs
is the standard non-linear realization: \`Maj\` provides the
non-linearity on the \`a\`-side branch of the round, complementing
\`Ch\`'s non-linearity on the \`e\`-side.

Role in the larger recurrence: paired with \`Σ0(a)\` to produce T2:

\`\`\`
T2 = Σ0(a) + Maj(a, b, c)   (mod 2³²)
\`\`\`

T2 contributes only to \`new_a\` (= T1 + T2). \`Maj\` is one of two
sources of round non-linearity (the other is \`Ch\` inside T1); without
either, the entire round would be linear over GF(2) and trivially
invertible.`,
  references: ["FIPS 180-4 §4.1.2 — Maj definition", "FIPS 180-4 §6.2.2 — Step 3 (T2)"],
};

const NARR_ROUND_T1: StepDocumentation = {
  name: "T1 = h + Σ1(e) + Ch(e,f,g) + K_t + W_t",
  summary: "5-way add mod 2³² combining the five T1 addends.",
  detail: `Per FIPS 180-4 §6.2.2 Step 3:

\`\`\`
T1 = h + Σ1(e) + Ch(e,f,g) + K_t + W_t   (mod 2³²)
\`\`\`

T1 feeds both new_a (= T1 + T2) and new_e (= d + T1). It is the
mixing core of SHA-256's compression round.`,
  references: ["FIPS 180-4 §6.2.2 — Step 3 (T1)"],
};

const NARR_ROUND_T2: StepDocumentation = {
  name: "T2 = Σ0(a) + Maj(a,b,c)",
  summary: "2-way add mod 2³² combining the two T2 addends.",
  detail: `Per FIPS 180-4 §6.2.2 Step 3:

\`\`\`
T2 = Σ0(a) + Maj(a,b,c)   (mod 2³²)
\`\`\`

T2 contributes only to new_a, not to new_e — this asymmetry is what
makes the working-variable cascade non-trivial.`,
  references: ["FIPS 180-4 §6.2.2 — Step 3 (T2)"],
};

const NARR_ROUND_NEW_A: StepDocumentation = {
  name: "new_a = T1 + T2 (next round's `a`)",
  summary: "Compute the next round's working variable `a` as T1 + T2 mod 2³².",
  detail: `Per FIPS 180-4 §6.2.2 Step 3:

\`\`\`
a' = T1 + T2   (mod 2³²)
\`\`\`

This is the "loaded" side of the working-variable update — it sums
BOTH the T1 mixing core (which carries \`Σ1(e), Ch(e,f,g), K_t, W_t\`,
\`h\`) AND the T2 helper (\`Σ0(a), Maj(a,b,c)\`). Every Σ, Ch, Maj, K_t,
and W_t contribution funnels here, so \`new_a\` is where the round's
diffusion concentrates.

The asymmetry vs \`new_e\` (which adds only T1 to d): the \`a\` slot
gets the maximum mixing on each round, the \`e\` slot only gets T1's
contribution. That asymmetry, combined with the slot-by-slot cascade
below, is what gives the cipher its avalanche after just a few rounds.

Cascade after this leaf: (a, b, c, d, e, f, g, h) ←
(new_a, a, b, c, new_e, e, f, g). new_a enters position 0; the old
\`h\` falls off.`,
  references: ["FIPS 180-4 §6.2.2 — Step 3 (variable update)"],
};

const NARR_ROUND_NEW_E: StepDocumentation = {
  name: "new_e = d + T1 (next round's `e`)",
  summary: "Compute the next round's working variable `e` as d + T1 mod 2³².",
  detail: `Per FIPS 180-4 §6.2.2 Step 3:

\`\`\`
e' = d + T1   (mod 2³²)
\`\`\`

The "light" side of the working-variable update — \`new_e\` receives
T1 (which carries the round's primary mixing) but NOT T2. The base
value is just \`d\`, the third working variable from the previous
round, with no extra mixing applied.

Why this asymmetry: \`d\` shifted into the \`e\` slot guarantees that
information from earlier rounds reaches the \`e\`-side branch
unmodified, while T1's contribution adds fresh mixing on top. Combined
with the \`a\`-side's heavier mixing (T1 + T2), this gives the round a
two-track structure — one track preserves old state, the other mixes
aggressively — that defeats simple algebraic attacks.

Cascade after this leaf: (a, b, c, d, e, f, g, h) ←
(new_a, a, b, c, new_e, e, f, g). new_e enters position 4 (the e slot);
the old \`d\` is consumed but its value lives on as the new \`e\`.`,
  references: ["FIPS 180-4 §6.2.2 — Step 3 (variable update)"],
};

const NARR_ROUND_REPACK: StepDocumentation = {
  name: "Cascade working variables (shift down by one slot)",
  summary: "Repack (new_a, a, b, c, new_e, e, f, g) — the next round's (a, b, c, d, e, f, g, h).",
  detail: `8-way concat that encodes the SHA-256 working-variable
cascade. Per FIPS 180-4 §6.2.2 Step 3, after each round:

\`\`\`
h ← g,  g ← f,  f ← e,  e ← d + T1,
d ← c,  c ← b,  b ← a,  a ← T1 + T2
\`\`\`

Equivalently: the next round's (a..h) is (new_a, a, b, c, new_e, e,
f, g). The previous \`h\` falls off; \`new_a\` enters at position 0;
\`new_e\` enters at position 4 (e's slot). This pure-rename is free
under the universal-port model — no extra step types needed.`,
  references: ["FIPS 180-4 §6.2.2 — Step 3 (variable cascade)"],
};

const NARR_ROUND_STATE_OUT: StepDocumentation = {
  name: "Round exit: bytes → state",
  summary: "Bridge: write the cascaded 32-byte working-variable buffer back into state.",
  detail: `Closes the round. State now holds the new (a, b, c, d, e,
f, g, h) — ready for the next round's body to read via state-to-bytes.`,
  references: ["FIPS 180-4 §6.2.2 — Step 3 end"],
};

// ── Final-add (7 distinct prose objects; 14 leaves total) ─────────────────

const NARR_FINAL_STATE_IN: StepDocumentation = {
  name: "Final-add: state → bytes (working variables)",
  summary: "Expose the post-round-63 working variables (32 bytes) on a port for splitting.",
  detail: `After all 64 rounds the working variables a..h are the
"compressed" hash for this block. Final-add will add H_0..H_7 to
them to produce the final digest (FIPS 180-4 §6.2.2 Step 4).`,
  references: ["FIPS 180-4 §6.2.2 — Step 4"],
};

const NARR_FINAL_SPLIT_WV: StepDocumentation = {
  name: "Split working variables (a..h)",
  summary: "Split the 32-byte buffer into 8 separate 4-byte working variable words.",
  detail: `Output port \`output_i\` carries the post-round-63 value
of the i-th working variable (for i = 0..7).`,
  references: ["FIPS 180-4 §6.2.2 — Step 4"],
};

const NARR_FINAL_FETCH_H: StepDocumentation = {
  name: "Final-add: fetch H array from aux",
  summary:
    'Load the 32-byte aux["H"] buffer of initial hash values to add back into the working variables.',
  detail: `H_0..H_7 (the SHA-256 initial hash values, FIPS 180-4
§5.3.3) are added back into the post-compression working variables
to produce the final digest. This loads the full 32-byte buffer; the
next leaf splits it.`,
  references: ["FIPS 180-4 §5.3.3 — Initial hash values"],
};

const NARR_FINAL_SPLIT_H: StepDocumentation = {
  name: "Split H_0..H_7",
  summary: 'Split the 32-byte aux["H"] buffer into 8 separate 4-byte H_i words.',
  detail: "Output port `output_i` carries H_i (for i = 0..7).",
  references: ["FIPS 180-4 §5.3.3 — Initial hash values"],
};

const NARR_FINAL_S_I: StepDocumentation = {
  name: "Digest word: hash_i = wv_i + H_i (mod 2³²)",
  summary: "Add the i-th initial hash value back into the i-th post-compression working variable.",
  detail: `Per FIPS 180-4 §6.2.2 Step 4, for each i ∈ 0..7:

\`\`\`
H_i ← H_i + a_i   (mod 2³²)
\`\`\`

where \`a_i\` is the i-th working variable after round 63 (a, b,
c, d, e, f, g, h corresponding to i = 0..7). For single-block scope
the new H_i IS the i-th digest word. Each of these 8 add-mod-32
leaves applies the rule for one specific i.`,
  references: ["FIPS 180-4 §6.2.2 — Step 4"],
};

const NARR_FINAL_ASSEMBLE: StepDocumentation = {
  name: "Assemble 32-byte digest",
  summary: "Concatenate hash_0..hash_7 into the final 32-byte SHA-256 output.",
  detail: `8-way concat producing the final 32-byte SHA-256 digest:

\`\`\`
digest = hash_0 || hash_1 || ... || hash_7
\`\`\`

For the "abc" KAT (FIPS 180-4 §A.1) this yields
\`ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\`.`,
  references: ["FIPS 180-4 §6.2.2 — Step 4 / §A.1 KAT"],
};

const NARR_FINAL_OUT: StepDocumentation = {
  name: "Final state (bytes → state)",
  summary: "Bridge: write the 32-byte digest back into state as the cipher's final output.",
  detail: `Closes the SHA-256 pipeline. State now holds the 32-byte
digest. This is what the UI shows as the cipher's output.`,
  references: ["FIPS 180-4 §6.2.2 — Step 4"],
};

// ─── Helper: shared port-input shapes (DRY) ───────────────────────────────

const port = (node: string, port: string): { readonly node: string; readonly port: string } => ({
  node,
  port,
});

// ─── Schedule body: 14 leaves per FES iteration ──────────────────────────
//
// Implements σ0/σ1 per FIPS 180-4 §4.1.2 + W_t = σ1(W_{t-2}) + W_{t-7}
// + σ0(W_{t-15}) + W_{t-16} per §6.2.2. The four lookback values come
// from aux["prior-N"] (auto-published by the FES-with-history runtime
// based on `lookbackOffsets=[2,7,15,16]`).
//
// Body exit state must be exactly `historyEntryByteLength = 4` bytes
// (the FES contract validates this). The final `bytes-to-state` leaf
// satisfies that.

const buildScheduleBody = (): readonly StepNode[] => [
  // ── Lookback fetches (4 leaves) ────────────────────────────────────
  {
    kind: "step",
    id: "fetch-p2",
    type: "aux-load-bytes@1",
    params: { auxName: "prior-2", byteLength: 4 },
    narrationOverride: NARR_SCHED_FETCH_P2,
  },
  {
    kind: "step",
    id: "fetch-p7",
    type: "aux-load-bytes@1",
    params: { auxName: "prior-7", byteLength: 4 },
    narrationOverride: NARR_SCHED_FETCH_P7,
  },
  {
    kind: "step",
    id: "fetch-p15",
    type: "aux-load-bytes@1",
    params: { auxName: "prior-15", byteLength: 4 },
    narrationOverride: NARR_SCHED_FETCH_P15,
  },
  {
    kind: "step",
    id: "fetch-p16",
    type: "aux-load-bytes@1",
    params: { auxName: "prior-16", byteLength: 4 },
    narrationOverride: NARR_SCHED_FETCH_P16,
  },
  // ── σ1(W_{t-2}) = ROTR^17(W_{t-2}) ⊕ ROTR^19(W_{t-2}) ⊕ SHR^10(W_{t-2}) ─
  {
    kind: "step",
    id: "sigma1-r17",
    type: "rotate-bits-right@1",
    params: { wordBits: 32, bits: 17 },
    portInputs: { input: port("fetch-p2", "output") },
    narrationOverride: NARR_SCHED_SIGMA1_R17,
  },
  {
    kind: "step",
    id: "sigma1-r19",
    type: "rotate-bits-right@1",
    params: { wordBits: 32, bits: 19 },
    portInputs: { input: port("fetch-p2", "output") },
    narrationOverride: NARR_SCHED_SIGMA1_R19,
  },
  {
    kind: "step",
    id: "sigma1-s10",
    type: "shift-bits-right@1",
    params: { wordBits: 32, bits: 10 },
    portInputs: { input: port("fetch-p2", "output") },
    narrationOverride: NARR_SCHED_SIGMA1_S10,
  },
  {
    kind: "step",
    id: "sigma1",
    type: "xor@1",
    params: { inputCount: 3 },
    portInputs: {
      operand0: port("sigma1-r17", "output"),
      operand1: port("sigma1-r19", "output"),
      operand2: port("sigma1-s10", "output"),
    },
    narrationOverride: NARR_SCHED_SIGMA1,
  },
  // ── σ0(W_{t-15}) = ROTR^7(W_{t-15}) ⊕ ROTR^18(W_{t-15}) ⊕ SHR^3(W_{t-15}) ─
  {
    kind: "step",
    id: "sigma0-r7",
    type: "rotate-bits-right@1",
    params: { wordBits: 32, bits: 7 },
    portInputs: { input: port("fetch-p15", "output") },
    narrationOverride: NARR_SCHED_SIGMA0_R7,
  },
  {
    kind: "step",
    id: "sigma0-r18",
    type: "rotate-bits-right@1",
    params: { wordBits: 32, bits: 18 },
    portInputs: { input: port("fetch-p15", "output") },
    narrationOverride: NARR_SCHED_SIGMA0_R18,
  },
  {
    kind: "step",
    id: "sigma0-s3",
    type: "shift-bits-right@1",
    params: { wordBits: 32, bits: 3 },
    portInputs: { input: port("fetch-p15", "output") },
    narrationOverride: NARR_SCHED_SIGMA0_S3,
  },
  {
    kind: "step",
    id: "sigma0",
    type: "xor@1",
    params: { inputCount: 3 },
    portInputs: {
      operand0: port("sigma0-r7", "output"),
      operand1: port("sigma0-r18", "output"),
      operand2: port("sigma0-s3", "output"),
    },
    narrationOverride: NARR_SCHED_SIGMA0,
  },
  // ── W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16} (mod 2^32) ──
  {
    kind: "step",
    id: "w-t",
    type: "add-mod-32@1",
    params: { inputCount: 4 },
    portInputs: {
      operand0: port("sigma1", "output"),
      operand1: port("fetch-p7", "output"),
      operand2: port("sigma0", "output"),
      operand3: port("fetch-p16", "output"),
    },
    narrationOverride: NARR_SCHED_W_T,
  },
  // ── FES body exit: 4-byte bytes-shape state ────────────────────────
  {
    kind: "step",
    id: "schedule-out",
    type: "bytes-to-state@1",
    params: {},
    portInputs: { input: port("w-t", "output") },
    narrationOverride: NARR_SCHED_OUT,
  },
];

// ─── Compression round body: 28 leaves per round ──────────────────────────
//
// Implements one round of SHA-256 compression per FIPS 180-4 §6.2.2.
// Reads state (32-byte working_vars a..h), reads W_t and K_t from aux,
// produces new state (the shifted working_vars new_a, a, b, c, new_e,
// e, f, g — renames-as-shift-down).

const buildCompressionRound = (t: number): StepNode => {
  const p = `round.${t}`;
  // Inline port helper that prepends the round prefix to source nodes
  // for the duration of this round build. Keeps the spec readable.
  const r = (node: string, portName: string) => port(`${p}.${node}`, portName);
  return {
    kind: "group",
    id: p,
    label: `Round ${t}`,
    // Default-collapse on first graph-view render (universal-port plan
    // Slice 2.6d follow-up, 2026-05-25). Slice 2.6d's decomposition
    // grew each compression round to 28 leaves; uncollapsed the 64
    // rounds put 1792 chips on the canvas on first visit, which is the
    // chip-wall failure mode Slice 2.6c plan F.1 flagged. The user can
    // expand any round via the chevron; that explicit expansion is
    // recorded in `LayoutSpec.expandedGroups` so the choice survives
    // subsequent re-runs. See `core/spec-defaults.ts` for the
    // effective-set algebra.
    defaultCollapsed: true,
    children: [
      // ── Extract a..h from state ────────────────────────────────────
      {
        kind: "step",
        id: `${p}.state-in`,
        type: "state-to-bytes@1",
        params: {},
        narrationOverride: NARR_ROUND_STATE_IN,
      },
      {
        kind: "step",
        id: `${p}.split`,
        type: "split-bytes@1",
        // 8 working-variable words; output0..output7 carry a..h respectively.
        params: { widths: [4, 4, 4, 4, 4, 4, 4, 4] },
        portInputs: { input: r("state-in", "output") },
        narrationOverride: NARR_ROUND_SPLIT,
      },
      // ── Fetch K_t from aux["K"] ────────────────────────────────────
      {
        kind: "step",
        id: `${p}.fetch-K`,
        type: "aux-load-bytes@1",
        params: { auxName: "K", byteLength: 256 },
        narrationOverride: NARR_ROUND_FETCH_K,
      },
      {
        kind: "step",
        id: `${p}.K_t`,
        type: "byte-slice@1",
        params: { sourceByteLength: 256, offset: 4 * t, length: 4 },
        portInputs: { input: r("fetch-K", "output") },
        narrationOverride: NARR_ROUND_K_T,
      },
      // ── Fetch W_t from aux["W"] ────────────────────────────────────
      {
        kind: "step",
        id: `${p}.fetch-W`,
        type: "aux-load-bytes@1",
        params: { auxName: "W", byteLength: 256 },
        narrationOverride: NARR_ROUND_FETCH_W,
      },
      {
        kind: "step",
        id: `${p}.W_t`,
        type: "byte-slice@1",
        params: { sourceByteLength: 256, offset: 4 * t, length: 4 },
        portInputs: { input: r("fetch-W", "output") },
        narrationOverride: NARR_ROUND_W_T,
      },
      // ── Σ1(e) = ROTR^6(e) ⊕ ROTR^11(e) ⊕ ROTR^25(e) ────────────────
      {
        kind: "step",
        id: `${p}.Sigma1-r6`,
        type: "rotate-bits-right@1",
        params: { wordBits: 32, bits: 6 },
        portInputs: { input: r("split", "output4") }, // e
        narrationOverride: NARR_ROUND_SIGMA1_R6,
      },
      {
        kind: "step",
        id: `${p}.Sigma1-r11`,
        type: "rotate-bits-right@1",
        params: { wordBits: 32, bits: 11 },
        portInputs: { input: r("split", "output4") },
        narrationOverride: NARR_ROUND_SIGMA1_R11,
      },
      {
        kind: "step",
        id: `${p}.Sigma1-r25`,
        type: "rotate-bits-right@1",
        params: { wordBits: 32, bits: 25 },
        portInputs: { input: r("split", "output4") },
        narrationOverride: NARR_ROUND_SIGMA1_R25,
      },
      {
        kind: "step",
        id: `${p}.Sigma1`,
        type: "xor@1",
        params: { inputCount: 3 },
        portInputs: {
          operand0: r("Sigma1-r6", "output"),
          operand1: r("Sigma1-r11", "output"),
          operand2: r("Sigma1-r25", "output"),
        },
        narrationOverride: NARR_ROUND_SIGMA1,
      },
      // ── Σ0(a) = ROTR^2(a) ⊕ ROTR^13(a) ⊕ ROTR^22(a) ────────────────
      {
        kind: "step",
        id: `${p}.Sigma0-r2`,
        type: "rotate-bits-right@1",
        params: { wordBits: 32, bits: 2 },
        portInputs: { input: r("split", "output0") }, // a
        narrationOverride: NARR_ROUND_SIGMA0_R2,
      },
      {
        kind: "step",
        id: `${p}.Sigma0-r13`,
        type: "rotate-bits-right@1",
        params: { wordBits: 32, bits: 13 },
        portInputs: { input: r("split", "output0") },
        narrationOverride: NARR_ROUND_SIGMA0_R13,
      },
      {
        kind: "step",
        id: `${p}.Sigma0-r22`,
        type: "rotate-bits-right@1",
        params: { wordBits: 32, bits: 22 },
        portInputs: { input: r("split", "output0") },
        narrationOverride: NARR_ROUND_SIGMA0_R22,
      },
      {
        kind: "step",
        id: `${p}.Sigma0`,
        type: "xor@1",
        params: { inputCount: 3 },
        portInputs: {
          operand0: r("Sigma0-r2", "output"),
          operand1: r("Sigma0-r13", "output"),
          operand2: r("Sigma0-r22", "output"),
        },
        narrationOverride: NARR_ROUND_SIGMA0,
      },
      // ── Ch(e,f,g) = (e ∧ f) ⊕ (¬e ∧ g) ─────────────────────────────
      {
        kind: "step",
        id: `${p}.Ch-not_e`,
        type: "not@1",
        params: {},
        portInputs: { input: r("split", "output4") }, // e
        narrationOverride: NARR_ROUND_CH_NOT_E,
      },
      {
        kind: "step",
        id: `${p}.Ch-e_and_f`,
        type: "and@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("split", "output4"), // e
          operand1: r("split", "output5"), // f
        },
        narrationOverride: NARR_ROUND_CH_E_AND_F,
      },
      {
        kind: "step",
        id: `${p}.Ch-note_and_g`,
        type: "and@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("Ch-not_e", "output"),
          operand1: r("split", "output6"), // g
        },
        narrationOverride: NARR_ROUND_CH_NOTE_AND_G,
      },
      {
        kind: "step",
        id: `${p}.Ch`,
        type: "xor@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("Ch-e_and_f", "output"),
          operand1: r("Ch-note_and_g", "output"),
        },
        narrationOverride: NARR_ROUND_CH,
      },
      // ── Maj(a,b,c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c) ───────────────────
      {
        kind: "step",
        id: `${p}.Maj-ab`,
        type: "and@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("split", "output0"), // a
          operand1: r("split", "output1"), // b
        },
        narrationOverride: NARR_ROUND_MAJ_AB,
      },
      {
        kind: "step",
        id: `${p}.Maj-ac`,
        type: "and@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("split", "output0"), // a
          operand1: r("split", "output2"), // c
        },
        narrationOverride: NARR_ROUND_MAJ_AC,
      },
      {
        kind: "step",
        id: `${p}.Maj-bc`,
        type: "and@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("split", "output1"), // b
          operand1: r("split", "output2"), // c
        },
        narrationOverride: NARR_ROUND_MAJ_BC,
      },
      {
        kind: "step",
        id: `${p}.Maj`,
        type: "xor@1",
        params: { inputCount: 3 },
        portInputs: {
          operand0: r("Maj-ab", "output"),
          operand1: r("Maj-ac", "output"),
          operand2: r("Maj-bc", "output"),
        },
        narrationOverride: NARR_ROUND_MAJ,
      },
      // ── T1 = h + Σ1(e) + Ch(e,f,g) + K_t + W_t (5-way add) ─────────
      {
        kind: "step",
        id: `${p}.T1`,
        type: "add-mod-32@1",
        params: { inputCount: 5 },
        portInputs: {
          operand0: r("split", "output7"), // h
          operand1: r("Sigma1", "output"),
          operand2: r("Ch", "output"),
          operand3: r("K_t", "output"),
          operand4: r("W_t", "output"),
        },
        narrationOverride: NARR_ROUND_T1,
      },
      // ── T2 = Σ0(a) + Maj(a,b,c) (2-way add) ────────────────────────
      {
        kind: "step",
        id: `${p}.T2`,
        type: "add-mod-32@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("Sigma0", "output"),
          operand1: r("Maj", "output"),
        },
        narrationOverride: NARR_ROUND_T2,
      },
      // ── new_a = T1 + T2, new_e = d + T1 ────────────────────────────
      {
        kind: "step",
        id: `${p}.new_a`,
        type: "add-mod-32@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("T1", "output"),
          operand1: r("T2", "output"),
        },
        narrationOverride: NARR_ROUND_NEW_A,
      },
      {
        kind: "step",
        id: `${p}.new_e`,
        type: "add-mod-32@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("split", "output3"), // d
          operand1: r("T1", "output"),
        },
        narrationOverride: NARR_ROUND_NEW_E,
      },
      // ── Repack working vars: shift down by one slot. Next round's a..h:
      //    (new_a, a, b, c, new_e, e, f, g). The previous h falls off.
      {
        kind: "step",
        id: `${p}.repack`,
        type: "concat@1",
        params: { inputCount: 8 },
        portInputs: {
          input0: r("new_a", "output"),
          input1: r("split", "output0"), // a (shifted into b's slot)
          input2: r("split", "output1"), // b → c
          input3: r("split", "output2"), // c → d
          input4: r("new_e", "output"),
          input5: r("split", "output4"), // e → f
          input6: r("split", "output5"), // f → g
          input7: r("split", "output6"), // g → h
        },
        narrationOverride: NARR_ROUND_REPACK,
      },
      {
        kind: "step",
        id: `${p}.state-out`,
        type: "bytes-to-state@1",
        params: {},
        portInputs: { input: r("repack", "output") },
        narrationOverride: NARR_ROUND_STATE_OUT,
      },
    ],
  };
};

// ─── Final-add: 13 leaves ──────────────────────────────────────────────────
//
// hash_i = working_vars[i] + H_i for i in 0..7 (mod 2^32). Per FIPS 180-4
// §6.2.2 step 4. The output is 32 bytes = the SHA-256 digest.

const buildFinalAddSteps = (): readonly StepNode[] => [
  {
    kind: "step",
    id: "final.state-in",
    type: "state-to-bytes@1",
    params: {},
    narrationOverride: NARR_FINAL_STATE_IN,
  },
  {
    kind: "step",
    id: "final.split-wv",
    type: "split-bytes@1",
    params: { widths: [4, 4, 4, 4, 4, 4, 4, 4] },
    portInputs: { input: port("final.state-in", "output") },
    narrationOverride: NARR_FINAL_SPLIT_WV,
  },
  {
    kind: "step",
    id: "final.fetch-H",
    type: "aux-load-bytes@1",
    params: { auxName: "H", byteLength: 32 },
    narrationOverride: NARR_FINAL_FETCH_H,
  },
  {
    kind: "step",
    id: "final.split-H",
    type: "split-bytes@1",
    params: { widths: [4, 4, 4, 4, 4, 4, 4, 4] },
    portInputs: { input: port("final.fetch-H", "output") },
    narrationOverride: NARR_FINAL_SPLIT_H,
  },
  // 8 × 2-way add-mod-32: s_i = wv_i + H_i
  ...Array.from(
    { length: 8 },
    (_, i): StepNode => ({
      kind: "step",
      id: `final.s${i}`,
      type: "add-mod-32@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: port("final.split-wv", `output${i}`),
        operand1: port("final.split-H", `output${i}`),
      },
      narrationOverride: NARR_FINAL_S_I,
    }),
  ),
  // Reassemble the 8 sums into a 32-byte hash.
  {
    kind: "step",
    id: "final.assemble",
    type: "concat@1",
    params: { inputCount: 8 },
    portInputs: Object.fromEntries(
      Array.from({ length: 8 }, (_, i) => [`input${i}`, port(`final.s${i}`, "output")]),
    ),
    narrationOverride: NARR_FINAL_ASSEMBLE,
  },
  {
    kind: "step",
    id: "final.out",
    type: "bytes-to-state@1",
    params: {},
    portInputs: { input: port("final.assemble", "output") },
    narrationOverride: NARR_FINAL_OUT,
  },
];

// ─── Spec builder ──────────────────────────────────────────────────────────

/**
 * Build the SHA-256 spec under the Slice 2.6d decomposed topology.
 *
 * Single-block only — supports messages whose total padded size is one
 * 64-byte block (i.e., message length ≤ 55 bytes per FIPS 180-4 §5.1.1
 * padding rules). Multi-block support lands in Slice 2.11.
 */
export const buildSha256Spec = (): CipherSpec => ({
  id: "sha-256@1",
  name: "SHA-256",
  stateShape: "bytes",
  // No key — hashes don't have keys. The `key` field is present but its
  // byteLength is 0; the UI's key editor will render an empty box.
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 0 },
  },
  steps: [
    // ─── Preprocessing ───────────────────────────────────────────────────
    // Plaintext entry bridge: expose initialState bytes on a port so
    // port-native primitives downstream can wire to them.
    {
      kind: "step",
      id: "plaintext-source",
      type: "state-to-bytes@1",
      params: {},
      narrationOverride: NARR_PLAINTEXT_SOURCE,
    },
    // Padding: input = plaintext, output = msg + 0x80 + zeros to ≡ 56 (mod 64).
    {
      kind: "step",
      id: "pad",
      type: "pad-with-byte@1",
      params: { padByte: 0x80, blockSize: 64, padTarget: 56 },
      portInputs: { input: port("plaintext-source", "output") },
      narrationOverride: NARR_PAD,
    },
    // Length suffix: data = padded bytes, length-source = ORIGINAL message
    // (per FIPS 180-4 §5.1.1, the suffix encodes the original message's
    // bit-length, not the padded length).
    {
      kind: "step",
      id: "length-append",
      type: "append-be64-length@1",
      params: {},
      portInputs: {
        data: port("pad", "output"),
        "length-source": port("plaintext-source", "output"),
      },
      narrationOverride: NARR_LENGTH_APPEND,
    },
    // ─── Bridge: padded block (64 bytes) → state ─────────────────────────
    // Required so the FES-with-history can seed its history from
    // parent-scope state.bytes.
    {
      kind: "step",
      id: "seed-schedule",
      type: "bytes-to-state@1",
      params: {},
      portInputs: { input: port("length-append", "output") },
      narrationOverride: NARR_SEED_SCHEDULE,
    },
    // ─── Message schedule (48 iterations, lookbackOffsets [2,7,15,16]) ────
    // 14-leaf decomposed body per iteration. After this, state = W[0..63]
    // (256 bytes — FES exit concatenates the full history).
    //
    // Default-collapse on first graph-view render (Slice 2.10c, 2026-05-25,
    // pre-emptive per Slice 2.6d follow-up's sequencing pin). 48 iterations
    // × 14 leaves = 672 chips uncollapsed — the chip-wall failure mode the
    // Slice 2.6c plan flagged. Same `defaultCollapsed: true` flag the 64
    // compression rounds already use (sha-256.ts:301). The two together
    // mean the SHA-256 graph view's first visit shows ~10 top-level chips
    // plus 64 collapsed round headers + 1 collapsed schedule header,
    // browseable; explicit user expansion writes through to
    // `LayoutSpec.expandedGroups` per the same `core/spec-defaults.ts`
    // algebra.
    {
      kind: "for-each-subgraph-with-history",
      id: "msg-schedule",
      label: "Message schedule W_0..W_63",
      iterationCount: 48,
      lookbackOffsets: [2, 7, 15, 16],
      historyEntryByteLength: 4,
      defaultCollapsed: true,
      children: buildScheduleBody(),
    },
    // ─── Q1 = (b): Publish W into aux["W"] ───────────────────────────────
    // State is the 256-byte W after the schedule exit. State-to-aux clones
    // it into aux["W"], where each compression round will read it from
    // (via aux-load-bytes + byte-slice). After this leaf, state is still
    // W (state-to-aux is identity on state); the next bridge below
    // overwrites state with the initial working variables.
    {
      kind: "step",
      id: "W-publish",
      type: "generic.state-to-aux-bytes@1",
      params: { auxName: "W" },
      narrationOverride: NARR_W_PUBLISH,
    },
    // ─── Load K into aux for the compression rounds ──────────────────────
    {
      kind: "step",
      id: "K-to-aux",
      type: "generic.aux-load@1",
      params: { auxName: "K", value: SHA256_K_BYTES },
      narrationOverride: NARR_K_TO_AUX,
    },
    // ─── Load H into aux for the final-add step ──────────────────────────
    {
      kind: "step",
      id: "H-to-aux",
      type: "generic.aux-load@1",
      params: { auxName: "H", value: SHA256_H_BYTES },
      narrationOverride: NARR_H_TO_AUX,
    },
    // ─── Initialize working variables from H_0..H_7 ──────────────────────
    // Emit H as a constant on a port, then bridge into state. After this,
    // state = working_vars (32 bytes) and compression rounds can begin.
    {
      kind: "step",
      id: "H-constant",
      type: "constant-load@1",
      params: { bytes: SHA256_H_BYTES },
      narrationOverride: NARR_H_CONSTANT,
    },
    {
      kind: "step",
      id: "init-working-vars",
      type: "bytes-to-state@1",
      params: {},
      portInputs: { input: port("H-constant", "output") },
      narrationOverride: NARR_INIT_WORKING_VARS,
    },
    // ─── 64 compression rounds (decomposed) ──────────────────────────────
    ...Array.from({ length: 64 }, (_, t) => buildCompressionRound(t)),
    // ─── Final add (decomposed): state (32 bytes wv) + aux["H"] → 32-byte hash
    ...buildFinalAddSteps(),
  ],
});

// ─── Public re-exports (consumers and tests) ──────────────────────────────

export const SHA256_INITIAL_HASH_VALUES = SHA256_H_WORDS;
export const SHA256_ROUND_CONSTANTS = SHA256_K_WORDS;
