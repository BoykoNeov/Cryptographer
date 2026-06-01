/**
 * Byte-native Speck32/64 key-schedule construction — key-schedule-decomposition
 * plan slice K2a (2026-06-01). The port-native replacement for the monolithic
 * `speck.key-schedule@1` executor.
 *
 * **Why decompose.** The monolith ran the whole Beaulieu et al. 2013 §3
 * schedule (split master key into m logical words; then per iteration
 * ROR/ADD/XOR/ROL/XOR over `(k_i, l_i)` to produce the next round key) inside
 * ONE executor — invisible to the trace. This builder expresses the same math
 * as a tree of port-native primitives so every sub-step is a scrubbable frame,
 * the same way `aes-key-schedule-builder-native.ts` (K1a) already does for
 * AES. The pedagogical payoff: the cipher's own ARX kernel runs visibly in
 * both the round body AND the schedule.
 *
 * **B-minimal (producer-only).** The recurrence is visible; a single
 * meta-bearing `speck.publish-round-keys@1` tail writes `aux["roundKey.0..21"]`
 * byte-identically to the monolith, so the round-body consumer
 * (`speck.round@1` reading `aux[roundKeyAux]` via `meta.auxReadPorts`) and the
 * shipped four Speck specs' round arrangement stay UNTOUCHED.
 *
 * **Byte-order codec at the I/O boundary (advisor pick 2026-06-01).** Speck's
 * BE-paper and LE-NSA conventions differ only in how master-key and round-key
 * bytes serialize — the word-level math is convention-invariant. The
 * decomposition follows the same posture: ONE `permute@1` input codec node
 * (different indices per byteOrder) reshapes the master-key memory layout
 * into the logical word order `[k_0, l_0, …, l_{m-2}]`, BE-encoded internally.
 * The body then operates uniformly on BE 16-bit words. For LE-NSA, ONE bulk
 * output codec sub-pipeline (concat → permute byte-swap → byte-slice ×
 * rounds) re-encodes the round keys back to LE bytes. For BE-paper the output
 * is direct (body's BE bytes match the published encoding). The codec leaves
 * carry explicit narrationOverrides so a learner sees exactly where the byte
 * convention adapts.
 *
 * **The recurrence (Beaulieu et al. 2013 §3), per iteration g = 0 …
 * rounds-2.** With master key `K = (l_{m-2}, …, l_0, k_0)`:
 *   - g.l-source: l_g (master-key word j=g+1 for g < m-1; else g.{g-(m-1)}.new-l)
 *   - g.k-source: k_g (master-key word 0 for g=0; else g.{g-1}.new-k)
 *   - g.rot-l = ROR(l-source, alpha)         [rotate-bits-right]
 *   - g.sum   = k-source + rot-l (mod 2^B)   [add-mod-16]
 *   - g.round-const = [hi(g), lo(g)] (BE)    [constant-load]
 *   - g.new-l = sum ⊕ round-const            [xor]
 *   - g.rol-k = ROL(k-source, beta)
 *           ≡ ROR(k-source, B - beta)        [rotate-bits-right]
 *   - g.new-k = rol-k ⊕ new-l                [xor]
 *
 * Output (the published round-key bank):
 *   roundKey.0       = master-key word 0 (k_0)
 *   roundKey.{g+1}   = g.new-k, for g = 0 .. rounds-2
 *
 * Total rounds round keys (22 for Speck32/64). NOTE: differs from AES (rounds+1)
 * — Speck has no initial pre-round key, hence the `speck.publish-round-keys@1`
 * step type's distinct count contract.
 *
 * **Parameterized by m and wordBits even though only Speck32/64 ships.**
 * Speck64/128 / Speck96/96 / Speck128/256 vary `wordBits` and `m`; future
 * variants drop into this builder without code changes. (Advisor flagged the
 * hardcoded `m=3-step l-lag` as a code-smell — the lag is `(m-1)` iterations,
 * and this builder uses that algebraic form throughout.)
 */

import type { PortBinding, StepDocumentation, StepNode } from "../core/types";
import type { SpeckByteOrder } from "../steps/speck-word-codec";

// ─── PortBinding + name helpers ───────────────────────────────────────────────

const port = (node: string, portName: string): PortBinding => ({ node, port: portName });
const ks = (suffix: string): string => `key-schedule.${suffix}`;

// ─── narrationOverride docs (Beaulieu et al. 2013 §3 friendly names) ──────────
// One shared static doc per role (the op is identical every iteration; the
// per-iteration specifics are the frame's byte values). Mirrors the SHA-256 /
// AES key-schedule narration idiom.

const NARR_LOAD_KEY: StepDocumentation = {
  name: "Load master key",
  summary: "Load the m-word master key from aux to seed the schedule.",
  detail: `## Load master key

The Speck master key has \`m\` words: \`K = (l_{m-2}, l_{m-3}, …, l_0, k_0)\`
in BE-paper memory order, or \`(k_0, l_0, …, l_{m-2})\` in LE-NSA order. This
leaf reads the raw bytes from \`aux["key"]\`; the input-codec leaf below then
reshapes them into the schedule's logical word order \`[k_0, l_0, …, l_{m-2}]\`
with BE per-word encoding.`,
  references: ["Beaulieu et al. 2013, §3 (Speck Key Schedule)"],
};

const NARR_INPUT_CODEC_BE = (m: number): StepDocumentation => ({
  name: "Decode BE-paper master key",
  summary: "Reverse word order: BE-paper memory layout → logical [k_0, l_0, …].",
  detail: `## Master-key codec (BE-paper)

BE-paper memory order is \`(l_${m - 2}, l_${m - 3}, …, l_0, k_0)\` with each word
big-endian. The decomposed schedule operates on logical word order
\`[k_0, l_0, …, l_${m - 2}]\` so this leaf reverses the word sequence (a per-word
gather permutation; bytes within each word stay big-endian). For Speck32/64
that's the 4 → 1 word permutation \`[6,7,4,5,2,3,0,1]\` over 8 master-key bytes.

The body downstream is byte-order-invariant up to the publish boundary; this
codec leaf concentrates the BE-paper convention in one explicit place.`,
  references: ["Beaulieu et al. 2013, §3"],
});

const NARR_INPUT_CODEC_LE = (m: number): StepDocumentation => ({
  name: "Decode LE-NSA master key",
  summary: "Byte-swap each word: LE-NSA memory layout → logical [k_0, l_0, …] BE.",
  detail: `## Master-key codec (LE-NSA)

LE-NSA memory order is \`(k_0, l_0, …, l_${m - 2})\` with each word
little-endian. The decomposed schedule operates on BE-encoded words
internally, so this leaf byte-swaps every word in place. For Speck32/64
that's the per-word byte permutation \`[1,0,3,2,5,4,7,6]\` over 8 master-key
bytes — the word order is already correct (k_0 first); only the byte order
within each word flips.

The body downstream operates uniformly on BE 16-bit words; this codec leaf
concentrates the LE-NSA convention in one explicit place.`,
  references: ["Beaulieu et al. 2013, §3", "NSA reference C / SUPERCOP"],
});

const NARR_MASTER_SPLIT = (m: number): StepDocumentation => ({
  name: "Split master key into words",
  summary: `Split the logical-ordered master key into ${m} 2-byte words.`,
  detail: `## Master-key split

After the input codec, the master key is laid out in logical order
\`[k_0, l_0, …, l_{m-2}]\` with BE per-word encoding. This split exposes
\`output0 = k_0\`, \`output1 = l_0\`, …, \`output{m-1} = l_{m-2}\` as
individual ports that the per-iteration body can wire to.`,
  references: ["Beaulieu et al. 2013, §3"],
});

// Note: there are no dedicated `g.l-source` / `g.k-source` LEAVES in the
// builder. The lag-(m-1) l-chain and the linear k-chain are expressed as
// direct port bindings to the upstream producer (master-split for the seed
// iterations; the prior iteration's new-l / new-k for the chained ones).
// Inserting passthrough leaves there would inflate the graph by ~42 chips
// for no pedagogical gain; the bindings ARE the chain.

const NARR_ROT_L: StepDocumentation = {
  name: "ROR(l_g, α)",
  summary: "Right-rotate l_g by α positions over a 16-bit word.",
  detail: `## ROR(l_g, α)

The first ARX step of the Speck recurrence: rotate the lower-key word
\`l_g\` right by \`α\` bits (α = 7 for Speck32/64; α = 8 for larger Speck
variants). Operates on a single 16-bit BE word.`,
  references: ["Beaulieu et al. 2013, §3 (forward round + key schedule)"],
};

const NARR_SUM: StepDocumentation = {
  name: "k_g + ROR(l_g, α) mod 2^B",
  summary: "Modular addition: k_g + ROR(l_g, α) mod 2^B.",
  detail: `## Modular addition

Add \`k_g\` and \`ROR(l_g, α)\` modulo \`2^B\` (B = wordBits). This is the
source of nonlinearity in Speck — the addition's carry chain propagates
key-dependent bits across the word, the cipher's defining substitute for an
S-box.`,
  references: ["Beaulieu et al. 2013, §3"],
};

const NARR_ROUND_CONST = (g: number): StepDocumentation => ({
  name: `Round counter ${g}`,
  summary: `The constant XORed into l_{g+m-1}: the round counter g = ${g}.`,
  detail: `## Round counter \`i = ${g}\`

Speck's key schedule XORs the round counter \`i\` into each generated \`l\`
word. Unlike AES's derived \`Rcon[g]\` table, Speck's constant IS the
iteration index — a beautifully simple way to break the schedule's symmetry.
This constant-load emits \`[hi(${g}), lo(${g})]\` (BE encoding of \`${g}\`)
for the XOR step below.`,
  references: ["Beaulieu et al. 2013, §3"],
});

const NARR_NEW_L: StepDocumentation = {
  name: "l_{g+m-1} = sum ⊕ i",
  summary: "New l word: (k_g + ROR(l_g, α)) ⊕ i.",
  detail: `## l_{g+m-1}

The new \`l\` word: \`l_{g+m-1} = (k_g + ROR(l_g, α)) ⊕ g\` — combining the
addition's nonlinear output with the round counter. This value also feeds
the next-line \`new-k\` derivation (the L-K coupling that makes the schedule
diffuse).`,
  references: ["Beaulieu et al. 2013, §3"],
};

const NARR_ROL_K: StepDocumentation = {
  name: "ROL(k_g, β)",
  summary: "Left-rotate k_g by β positions. Implemented as ROR by (B - β).",
  detail: `## ROL(k_g, β)

The second rotation in Speck's recurrence: rotate the upper-key word
\`k_g\` LEFT by \`β\` bits (β = 2 for Speck32/64; β = 3 for larger
Speck variants). Implemented here as a right-rotation by \`B - β\` bits —
\`ROL(x, β) = ROR(x, B - β)\` over a B-bit word — so a single
\`rotate-bits-right\` primitive serves both rotation directions.`,
  references: ["Beaulieu et al. 2013, §3"],
};

const NARR_NEW_K: StepDocumentation = {
  name: "k_{g+1} = ROL(k_g, β) ⊕ l_{g+m-1}",
  summary: "Next round-key word: ROL(k_g, β) ⊕ l_{g+m-1}.",
  detail: `## k_{g+1}

The new round-key word — published to \`aux["roundKey.{g+1}"]\` at the
schedule's tail. Combines the rotated previous round-key word with the
just-derived \`l_{g+m-1}\` so the schedule mixes both key-word lanes at
every step.`,
  references: ["Beaulieu et al. 2013, §3"],
};

const NARR_OUTPUT_CONCAT: StepDocumentation = {
  name: "Concatenate round keys (LE codec input)",
  summary: "Concatenate all round-key words into one buffer for the output codec.",
  detail: `## Concatenate round keys

For LE-NSA mode, the body produces BE-encoded round-key words; before
publishing as LE-NSA bytes, all words go through one bulk byte-swap. This
concat assembles the \`rounds × 2 = ${22 * 2}\`-byte buffer the codec
operates on.`,
  references: ["Beaulieu et al. 2013, §3", "NSA reference C / SUPERCOP"],
};

const NARR_OUTPUT_CODEC_LE: StepDocumentation = {
  name: "Encode LE-NSA round keys",
  summary: "Byte-swap each word: internal BE → LE-NSA published encoding.",
  detail: `## Round-key codec (LE-NSA)

LE-NSA publishes each round-key word with bytes in little-endian order
(low byte first in memory). The body produces BE-encoded bytes; this bulk
codec leaf byte-swaps every word in place via the per-word permutation
\`[1,0,3,2,…]\` over the concatenated round-key buffer.

This is the second of two codec leaves localizing the LE-NSA convention;
the first reshapes the master key, this one re-encodes the published
output. The body in between is byte-order-invariant BE math.`,
  references: ["Beaulieu et al. 2013, §3", "NSA reference C / SUPERCOP"],
};

const NARR_OUTPUT_SLICE = (r: number, rounds: number): StepDocumentation => ({
  name: `Slice round key ${r}`,
  summary: `Extract round-key word ${r} from the codec'd round-key stream.`,
  detail: `## Round key ${r}

Extract the \`r = ${r}\` round-key word (2 bytes for Speck32/64) from the
concatenated and byte-swapped round-key stream. The publish tail's
\`key${r}\` input port reads this slice; the meta-bearing
\`speck.publish-round-keys@1\` then routes it to \`aux["roundKey.${r}"]\`.
Total rounds: ${rounds}.`,
  references: ["Beaulieu et al. 2013, §3"],
});

// ─── Codec index helpers ──────────────────────────────────────────────────────

/**
 * Build the input-codec permute indices for BE-paper master key.
 *
 * BE-paper memory layout: `(l_{m-2}, l_{m-3}, …, l_0, k_0)`, each word
 * BE-encoded. We want logical layout `[k_0, l_0, …, l_{m-2}]`, BE-encoded.
 *
 * That's a per-word REVERSE of the memory order — bytes within each word
 * stay big-endian (no per-word byte-swap). For m=4 the indices map:
 * memory `[l_2_hi, l_2_lo, l_1_hi, l_1_lo, l_0_hi, l_0_lo, k_0_hi, k_0_lo]`
 * → logical `[k_0_hi, k_0_lo, l_0_hi, l_0_lo, l_1_hi, l_1_lo, l_2_hi, l_2_lo]`,
 * i.e. indices `[6,7,4,5,2,3,0,1]`.
 *
 * General form: logical word j (j=0..m-1) comes from memory word `m-1-j`;
 * within each word, the two bytes stay in `[hi, lo]` order.
 */
const beInputCodecIndices = (m: number): number[] => {
  const indices: number[] = [];
  for (let j = 0; j < m; j++) {
    const memWord = m - 1 - j;
    indices.push(memWord * 2, memWord * 2 + 1);
  }
  return indices;
};

/**
 * Build the input-codec permute indices for LE-NSA master key.
 *
 * LE-NSA memory layout: `(k_0, l_0, l_1, …, l_{m-2})`, each word LE-encoded.
 * We want logical layout `[k_0, l_0, …, l_{m-2}]`, BE-encoded — same word
 * order, but each word's bytes flipped.
 *
 * For m=4 the indices `[1,0,3,2,5,4,7,6]` map
 * memory `[k_0_lo, k_0_hi, l_0_lo, l_0_hi, l_1_lo, l_1_hi, l_2_lo, l_2_hi]`
 * → logical `[k_0_hi, k_0_lo, l_0_hi, l_0_lo, l_1_hi, l_1_lo, l_2_hi, l_2_lo]`.
 */
const leInputCodecIndices = (m: number): number[] => {
  const indices: number[] = [];
  for (let j = 0; j < m; j++) {
    indices.push(j * 2 + 1, j * 2);
  }
  return indices;
};

/**
 * Build the output-codec permute indices for LE-NSA round-key output. The
 * body produces a `rounds × 2`-byte BE-encoded stream; LE-NSA publishes each
 * word with bytes flipped. So indices `[1,0,3,2,…,2r+1, 2r, …]` byte-swap
 * every word in place over the whole stream.
 */
const leOutputCodecIndices = (rounds: number): number[] => {
  const indices: number[] = [];
  for (let r = 0; r < rounds; r++) {
    indices.push(r * 2 + 1, r * 2);
  }
  return indices;
};

// ─── Builder ──────────────────────────────────────────────────────────────────

/**
 * Build the decomposed Speck32/64 key schedule as a single (default-collapsed)
 * `key-schedule` group. Writes `aux["roundKey.0..rounds-1"]` via the
 * `speck.publish-round-keys@1` tail — byte-identical to the legacy monolith
 * for both byte-order conventions.
 *
 * @param rounds     Total round-key count (22 for Speck32/64). The schedule
 *                   emits `rounds` round keys with `rounds-1` ARX iterations.
 * @param m          Number of master-key words. Speck32/64 = 4.
 * @param wordBits   Word width in bits. Speck32/64 = 16 (today's only shipped
 *                   variant; future Speck variants tune this).
 * @param alpha      Right-rotation amount on l. Speck32/64 = 7.
 * @param beta       Left-rotation amount on k. Speck32/64 = 2.
 * @param byteOrder  "be-paper" or "le-nsa" — the master-key + round-key
 *                   serialization convention.
 */
export function buildSpeck32_64KeyScheduleNative(
  rounds: number,
  m: number,
  wordBits: number,
  alpha: number,
  beta: number,
  byteOrder: SpeckByteOrder,
): StepNode {
  if (!Number.isInteger(rounds) || rounds < 2) {
    throw new Error(
      `buildSpeck32_64KeyScheduleNative: rounds must be an integer ≥ 2 (got ${rounds})`,
    );
  }
  if (!Number.isInteger(m) || m < 2) {
    throw new Error(`buildSpeck32_64KeyScheduleNative: m must be an integer ≥ 2 (got ${m})`);
  }
  if (wordBits !== 16) {
    // Today only Speck32/64 (wordBits=16) ships; the `add-mod-16@1` primitive
    // is hardcoded 16-bit, mirroring `add-mod-32@1`'s posture. Future variants
    // would need `add-mod-64@1` etc. — out of scope for K2a.
    throw new Error(
      `buildSpeck32_64KeyScheduleNative: only wordBits=16 is supported today (got ${wordBits})`,
    );
  }
  if (!Number.isInteger(alpha) || alpha < 1 || alpha >= wordBits) {
    throw new Error(
      `buildSpeck32_64KeyScheduleNative: alpha must be in [1, wordBits) (got ${alpha})`,
    );
  }
  if (!Number.isInteger(beta) || beta < 1 || beta >= wordBits) {
    throw new Error(
      `buildSpeck32_64KeyScheduleNative: beta must be in [1, wordBits) (got ${beta})`,
    );
  }

  const wordBytes = wordBits / 8; // 2 for Speck32/64
  const masterKeyBytes = m * wordBytes;
  const lag = m - 1; // Speck's iteration-lag on the l-chain
  const iterations = rounds - 1; // ARX iterations: g = 0..iterations-1
  const children: StepNode[] = [];

  // ── Master-key load (raw memory-order bytes from aux). ────────────────────
  children.push({
    kind: "step",
    id: ks("load-key"),
    type: "aux-load-bytes@1",
    params: { auxName: "key", byteLength: masterKeyBytes },
    narrationOverride: NARR_LOAD_KEY,
  });

  // ── Input codec (one leaf in BOTH modes, different indices). ──────────────
  // Reshapes the master key from MEMORY layout to LOGICAL [k_0, l_0, …]
  // with internal BE per-word encoding. See the codec-index helpers for the
  // derivation; both modes are non-trivial permutations.
  const inputCodecIndices =
    byteOrder === "be-paper" ? beInputCodecIndices(m) : leInputCodecIndices(m);
  children.push({
    kind: "step",
    id: ks("input-codec"),
    type: "permute@1",
    params: { indices: inputCodecIndices },
    portInputs: { input: port(ks("load-key"), "output") },
    narrationOverride: byteOrder === "be-paper" ? NARR_INPUT_CODEC_BE(m) : NARR_INPUT_CODEC_LE(m),
  });

  // ── Master-key split into individual logical words. ───────────────────────
  // After the codec, output{j} carries the BE encoding of logical word j:
  // output0 = k_0; output1 = l_0; …; output{m-1} = l_{m-2}.
  children.push({
    kind: "step",
    id: ks("master-split"),
    type: "split-bytes@1",
    params: { widths: Array.from({ length: m }, () => wordBytes) },
    portInputs: { input: port(ks("input-codec"), "output") },
    narrationOverride: NARR_MASTER_SPLIT(m),
  });

  // ── Per-iteration body, g = 0..iterations-1. ──────────────────────────────
  // Each iteration emits two products: `g.new-l` (for downstream l-chain
  // reading by iteration g + (m-1)) and `g.new-k` (the round-key word for
  // index g+1; chained linearly to g+1's k-source). The l-chain has lag
  // (m-1) — iteration g writes l_{g+m-1}, which iteration g+(m-1) reads as
  // its l-source.

  for (let g = 0; g < iterations; g++) {
    const gp = `g${g}`;
    const id = (leaf: string): string => ks(`${gp}.${leaf}`);

    // l-source: master-key word l_g for g < lag (= m-1), else previous
    // iteration's new-l. master-split exposes logical word j on port
    // `output{j}`; l_g corresponds to logical word `g + 1` (output0 = k_0,
    // output1 = l_0, output2 = l_1, …, output{m-1} = l_{m-2}). When
    // g + 1 ≥ m, l_g came from a prior iteration's new-l output.
    const lSource: PortBinding =
      g < lag
        ? port(ks("master-split"), `output${g + 1}`)
        : port(ks(`g${g - lag}.new-l`), "output");
    // No dedicated `g.l-source` leaf — l-source is a pure binding to the
    // upstream port. (Adding a leaf would just be a passthrough; keep the
    // graph leaner.)

    // k-source: master-key word k_0 for g = 0, else previous iteration's
    // new-k.
    const kSource: PortBinding =
      g === 0 ? port(ks("master-split"), "output0") : port(ks(`g${g - 1}.new-k`), "output");
    // Same posture as l-source — no dedicated leaf.

    // ROR(l_g, alpha)
    children.push({
      kind: "step",
      id: id("rot-l"),
      type: "rotate-bits-right@1",
      params: { bits: alpha, wordBits },
      portInputs: { input: lSource },
      narrationOverride: NARR_ROT_L,
    });

    // sum = k_g + ROR(l_g, alpha) mod 2^B
    children.push({
      kind: "step",
      id: id("sum"),
      type: "add-mod-16@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: kSource,
        operand1: port(id("rot-l"), "output"),
      },
      narrationOverride: NARR_SUM,
    });

    // round-const: BE encoding of g (16-bit). For g < 256 the bytes are
    // [0, g]; for g ≥ 256 (hypothetical larger variants) the high byte
    // is non-zero. Speck32/64 has g ≤ 20 so always [0, g].
    children.push({
      kind: "step",
      id: id("round-const"),
      type: "constant-load@1",
      params: { bytes: [(g >>> 8) & 0xff, g & 0xff] },
      narrationOverride: NARR_ROUND_CONST(g),
    });

    // new-l = sum XOR g
    children.push({
      kind: "step",
      id: id("new-l"),
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: port(id("sum"), "output"),
        operand1: port(id("round-const"), "output"),
      },
      narrationOverride: NARR_NEW_L,
    });

    // ROL(k_g, beta) ≡ ROR(k_g, B - beta) over a B-bit word.
    children.push({
      kind: "step",
      id: id("rol-k"),
      type: "rotate-bits-right@1",
      params: { bits: wordBits - beta, wordBits },
      portInputs: { input: kSource },
      narrationOverride: NARR_ROL_K,
    });

    // new-k = ROL(k_g, beta) XOR new-l
    children.push({
      kind: "step",
      id: id("new-k"),
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: port(id("rol-k"), "output"),
        operand1: port(id("new-l"), "output"),
      },
      narrationOverride: NARR_NEW_K,
    });
  }

  // ── Output codec + publish tail. ──────────────────────────────────────────
  // Asymmetric across byteOrder (advisor pick): BE-paper wires directly from
  // body to publish (body's BE bytes match the published BE-paper encoding);
  // LE-NSA goes through concat → permute byte-swap → byte-slice × rounds.
  //
  // Publish-tail input port `key0` reads master-split.output0 (= k_0) for
  // both modes. `key{r}` for r >= 1 reads g{r-1}.new-k (for r = 1..rounds-1).
  // ROUND-COUNT KEY: total rounds round keys; iterations = rounds - 1 ARX
  // iterations produce keys 1..rounds-1; key0 is the master-key word.

  const publishInputs: Record<string, PortBinding> = {};

  if (byteOrder === "be-paper") {
    // Direct wiring: each new-k (and k_0) port-feeds the corresponding publish
    // input.
    publishInputs.key0 = port(ks("master-split"), "output0");
    for (let g = 0; g < iterations; g++) {
      publishInputs[`key${g + 1}`] = port(ks(`g${g}.new-k`), "output");
    }
  } else {
    // LE-NSA: concat all round-key words → bulk byte-swap → per-round byte-slice.
    const concatInputs: Record<string, PortBinding> = {};
    concatInputs.input0 = port(ks("master-split"), "output0");
    for (let g = 0; g < iterations; g++) {
      concatInputs[`input${g + 1}`] = port(ks(`g${g}.new-k`), "output");
    }
    children.push({
      kind: "step",
      id: ks("output-concat"),
      type: "concat@1",
      params: { inputCount: rounds },
      portInputs: concatInputs,
      narrationOverride: NARR_OUTPUT_CONCAT,
    });

    children.push({
      kind: "step",
      id: ks("output-codec"),
      type: "permute@1",
      params: { indices: leOutputCodecIndices(rounds) },
      portInputs: { input: port(ks("output-concat"), "output") },
      narrationOverride: NARR_OUTPUT_CODEC_LE,
    });

    const streamBytes = rounds * wordBytes;
    for (let r = 0; r < rounds; r++) {
      const sliceId = ks(`rk-slice-${r}`);
      children.push({
        kind: "step",
        id: sliceId,
        type: "byte-slice@1",
        params: { sourceByteLength: streamBytes, offset: r * wordBytes, length: wordBytes },
        portInputs: { input: port(ks("output-codec"), "output") },
        narrationOverride: NARR_OUTPUT_SLICE(r, rounds),
      });
      publishInputs[`key${r}`] = port(sliceId, "output");
    }
  }

  // ── Publish tail (the one surviving meta): aux["roundKey.0..rounds-1"]. ───
  children.push({
    kind: "step",
    id: ks("publish"),
    type: "speck.publish-round-keys@1",
    params: { outputPrefix: "roundKey", rounds },
    portInputs: publishInputs,
  });

  return {
    kind: "group",
    id: "key-schedule",
    label: "Key Schedule",
    // Default-collapse so the ~150 recurrence chips don't wall the canvas on
    // first graph render (same posture as SHA-256's rounds + AES's
    // decomposed key schedule).
    defaultCollapsed: true,
    children,
  };
}
