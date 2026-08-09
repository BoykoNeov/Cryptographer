/**
 * The number-theoretic transform over `R_q = Z_q[X]/(X²⁵⁶+1)`, `q = 3329` —
 * the app's first post-quantum object, and the arithmetic engine underneath
 * ML-KEM. `docs/plans/unified-stargazing-quasar.md`, P1.
 *
 * ## What this is, in one paragraph
 *
 * Multiplying two 256-coefficient polynomials the schoolbook way costs 65,536
 * coefficient multiplications. The NTT is a change of representation that makes
 * it cost 128 — the same trick the FFT plays for signal processing, but done in
 * integers modulo a prime instead of in complex numbers, so it is exact and has
 * no rounding. ML-KEM does not merely *use* the NTT for speed: its public keys
 * and ciphertexts are *stored* in the transformed domain, so this is not an
 * optimization tucked inside the algorithm, it is part of the data format.
 *
 * Forward transform = "encrypt", inverse = "decrypt". The transform is a genuine
 * direction pair, so it fits the app's two-slot model exactly.
 *
 * ## Structure: seven layers, and why not eight
 *
 * ```
 *   layer 1:   1 group  of 256 coefficients   (block 512 bytes)
 *   layer 2:   2 groups of 128                (block 256 bytes)
 *   layer 3:   4 groups of  64                (block 128)
 *   layer 4:   8 groups of  32                (block  64)
 *   layer 5:  16 groups of  16                (block  32)
 *   layer 6:  32 groups of   8                (block  16)
 *   layer 7:  64 groups of   4                (block   8)
 *              ───
 *             127 groups total, one twiddle factor each
 * ```
 *
 * Each layer is ONE `iterate` node, which the runtime runs once per group. The
 * unrolled alternative is ~890 spec nodes per polynomial against this form's
 * ~60, and spec-node count is what the app's re-run cost is made of.
 *
 * A full decomposition would be eight layers, ending in 256 constants. It stops
 * at seven because `q − 1 = 2⁸ · 13` admits no primitive 512th root of unity, so
 * the last split is impossible — the transform ends at **128 degree-1
 * polynomials**, and the inverse's final scaling is by `128⁻¹`, not `256⁻¹`.
 * See `mlkem-constants.ts`.
 *
 * ## The twiddle factors ride the chain — a deliberate choice, not a forcing
 *
 * Each of the 127 groups needs its own ζ. They arrive as a **256-byte table on
 * the iterate's cross-iteration chain, rotating by one entry per group**, and
 * the final cursor position passes from each layer to the next through
 * `chainOutput` → `chainInput`. That is CBC's chain machinery and OFB's carry,
 * unchanged: no runtime change, no new mechanism.
 *
 * The alternative was to read `aux["blockIndex"]` (which `runtime.ts` does
 * publish on every port-mode iterate) and index a ζ table inside an executor.
 * It computes the same coefficients and would pass every test in
 * `tests/ntt-3329-256-kat.test.ts`. **What it would not do is let the learner
 * watch the twiddle factors advance** — which is the one thing this view exists
 * to show, and the Context section's promise. A future reader who finds the
 * rotating table baroque should know that "simplifying" it deletes the feature.
 *
 * (The aux route is also latently fragile: nested iterates overwrite
 * `blockIndex`, so it would break silently the moment an NTT were placed inside
 * another loop — exactly the class of breakage the port-scope rules exist to
 * prevent.)
 *
 * ## Why `q` reaches the butterfly through aux, and could not do otherwise
 *
 * `q` is published on `spec.cipherConstants`, which the runtime seeds into the
 * global aux map before any step runs, and each butterfly reads it with an
 * `aux-load-bytes@1` INSIDE the loop body.
 *
 * This is forced, not stylistic. The runtime seeds an iterate body's scope with
 * exactly that iterate's own `in` and `chain` ports (`runtime.ts`, the
 * `iterSeed` map) — port flow cannot cross a group scope. A top-level
 * `constant-load@1` wired down into the body would throw. It is the ChaCha20
 * CSPRNG's seed lesson and the Twofish subkey precondition, met a third time.
 *
 * It costs nothing pedagogically: `cipherConstants` is still one editable source
 * of truth, so changing `q` in the app moves all 127 groups in lockstep.
 *
 * ## The two butterflies
 *
 * Forward — Cooley–Tukey (FIPS 203 Algorithm 9):
 * ```
 * t   = ζ · hi
 * lo' = lo + t
 * hi' = lo − t
 * ```
 *
 * Inverse — Gentleman–Sande (FIPS 203 Algorithm 10):
 * ```
 * lo' = lo + hi
 * hi' = ζ · (hi − lo)
 * ```
 *
 * They are not the same shape with a sign flipped: the forward multiplies
 * *before* combining, the inverse *after*. That, plus the layers running in the
 * opposite order and the cursor rotating the opposite way, is the entire
 * difference between the two specs.
 *
 * ## Verification
 *
 * `tests/ntt-3329-256-kat.test.ts`, ranked strongest first: direct CRT
 * evaluation against the transform's *definition* (sharing no code with the
 * butterflies), then the convolution theorem, and only last the round trip —
 * which a pair of matched-wrong implementations passes.
 */

import type { CipherSpec, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { port } from "./block-cipher-core";
import {
  COEFF_BYTES,
  ML_KEM_N,
  ML_KEM_Q,
  NTT_LAYERS,
  N_INV_128,
  N_INV_BYTES,
  POLY_BYTES,
  Q_BYTES,
  ZETA_TABLE_BYTES,
} from "./mlkem-constants";

// ─── Node ids ─────────────────────────────────────────────────────────────
//
// Exported because the KAT addresses nodes by id and a silent rename would
// break it in a way the type checker cannot see.

/** Top-level: the ζ table fetched out of aux. */
export const NTT_ZETA_TABLE_ID = "zeta-table";
/** Forward only: the one-entry pre-rotation that parks the cursor on ζ¹. */
export const NTT_CURSOR_SPLIT_ID = "cursor-split";
export const NTT_CURSOR_ID = "cursor";
/** Inverse only: the final `× 128⁻¹` scaling and the two constants it reads. */
export const INTT_SCALE_ID = "scale";
export const INTT_NINV_ID = "ninv";
export const INTT_SCALE_Q_ID = "scale-q";

/** Layer `n` (1-based) — the iterate node itself. */
export const nttLayerId = (n: number): string => `layer${n}`;

/** The chain port each layer publishes its final cursor position on. */
const CURSOR_PORT = "cursor";

/** Vector-step params. Big-endian per coefficient — the app's standing "a port
 *  carries a non-negative big-endian integer" convention. */
const VEC_PARAMS = { coeffBytes: COEFF_BYTES, littleEndian: false } as const;

/** Coefficients paired by layer `n`: 128, 64, 32, … 2. */
const layerLen = (n: number): number => ML_KEM_N / 2 ** n;

// ─── Narration ────────────────────────────────────────────────────────────
//
// Per-leaf `narrationOverride`, the LCG's approach: the registry doc says what
// the primitive IS, and these say what this particular occurrence is DOING. The
// butterfly is the teaching content of the whole phase, so it gets the prose.

const narrZetaTable: StepDocumentation = {
  name: "The 128 twiddle factors",
  summary: "ζ⁰ … ζ¹²⁷ — the table of roots of unity every layer draws from.",
  detail: `## The numbers that make the transform work

All 128 twiddle factors, fetched as one 256-byte table.

Every entry is a power of **17**, and 17 is special modulo 3329: raise it to the
128th power and you get 3328, which is −1 here; raise it to the 256th and you get
1. A number that returns to 1 after exactly 256 steps is precisely what lets a
256-coefficient polynomial be taken apart and put back together.

## They are not in the order you would guess

The table is not ζ⁰, ζ¹, ζ², ζ³ in ascending powers. Entry \`i\` is
\`17\` raised to the power **bit-reverse-7 of i**:

\`\`\`
ZETAS[1] = 17^64  = 1729
ZETAS[2] = 17^32  = 2580
ZETAS[3] = 17^96  = 3289
\`\`\`

That scrambled order is exactly the order the layers below consume them in — one
per butterfly group, first to last, never skipping and never indexing. It is why
the table can simply advance by one entry each time instead of computing an
address.

Published as FIPS 203, Appendix A.`,
  references: ["FIPS 203 Appendix A — the ζ table", "FIPS 203 Algorithm 9 — NTT"],
};

const narrCursorSplit: StepDocumentation = {
  name: "Set the cursor to ζ¹",
  summary: "Takes ζ⁰ = 1 off the front so the first layer starts on ζ¹.",
  detail: `## Skipping the first entry

The table starts with \`ZETAS[0] = 1\`, and multiplying by 1 does nothing — so
the transform never uses it. The first butterfly group wants \`ZETAS[1]\`.

This step and the one below it move that leading entry to the back, leaving the
cursor parked where the first layer needs it. From here on, every group takes
whatever is at the front and rotates the table by one.`,
  references: [],
};

const narrCursor: StepDocumentation = {
  name: "The rotating table",
  summary: "ζ¹ first, ζ⁰ moved to the back — the cursor the seven layers share.",
  detail: `## One table, 127 consumers

This 256-byte value is handed to layer 1 and then passed from layer to layer,
each one leaving it advanced by however many groups it ran. Layer 1 runs one
group and consumes ζ¹; layer 2 runs two and consumes ζ² and ζ³; layer 7 runs
sixty-four. By the end all 127 have been used, in order, exactly once.

Watch it in the trace: this is the same wire that carries CBC's chaining value
and OFB's keystream register. Nothing was added to the runtime to make the
transform work — a loop that carries a value from one pass to the next was
already there.`,
  references: [],
};

/**
 * Layer geometry, resolved once per layer and threaded into both the body
 * builder and the narration.
 *
 * `displayIndex` and `len` must be carried separately, because the inverse runs
 * the layers in the opposite order: its layer 1 has the SMALLEST pairing
 * distance (2), which is the forward layer 7's. Deriving one from the other
 * inside a narrator was the first version of this file and it printed the wrong
 * layer number on every inverse frame.
 */
type LayerGeometry = {
  /** 1-based position in the spec, as the label shows it. */
  readonly displayIndex: number;
  /** Pairing distance in coefficients: 128 … 2. */
  readonly len: number;
  /** Butterfly groups this layer runs: 1 … 64. */
  readonly groups: number;
  /** Bytes one group spans. */
  readonly blockBytes: number;
  /** Node-id prefix — always keyed on `displayIndex`, never on `len`. */
  readonly id: string;
};

const geometryFor = (displayIndex: number, len: number): LayerGeometry => ({
  displayIndex,
  len,
  groups: ML_KEM_N / (2 * len),
  blockBytes: len * 2 * COEFF_BYTES,
  id: nttLayerId(displayIndex),
});

const narrLayerSplit = (g: LayerGeometry): StepDocumentation => ({
  name: `Split into halves of ${g.len}`,
  summary: `Cuts this group's ${g.len * 2} coefficients into a low half and a high half.`,
  detail: `## The pairing

Layer ${g.displayIndex} pairs coefficient \`j\` with coefficient \`j + ${g.len}\`.
Cutting the group in half is how that pairing is expressed: everything in the low
half meets the element at the same position in the high half.

The pairing distance changes by a factor of two at every layer, running
${ML_KEM_N / 2} … 2 in the forward direction and 2 … ${ML_KEM_N / 2} in the
inverse. That is the whole shape of the transform: one direction starts by
combining coefficients that are far apart and finishes with neighbours, and the
other undoes it in reverse.`,
  references: ["FIPS 203 Algorithm 9"],
});

const narrZetaRead = (g: LayerGeometry): StepDocumentation => ({
  name: "Take this group's ζ",
  summary: "Reads this group's twiddle factor off the table; the rest is what remains.",
  detail: `## Two bytes off the end

Two bytes of the rotating table are this group's twiddle factor. The other 254
are handed to the step that rotates them round.

Layer ${g.displayIndex} runs ${g.groups} group${g.groups === 1 ? "" : "s"}, so it
consumes ${g.groups} of the 127 factors before passing the table on.

**Scrub through the groups and watch this value change.** It is the only thing
that distinguishes one butterfly from another — every group runs identical
arithmetic on different coefficients with a different ζ.`,
  references: [],
});

const narrAdvance: StepDocumentation = {
  name: "Advance the cursor",
  summary: "Moves the used factor to the back, so the next group finds the next one in front.",
  detail: `## Rotate by one entry

The factor just consumed goes to the back of the table and everything else moves
up two bytes. That is all "get the next twiddle factor" means here — no counter,
no index arithmetic, no lookup.

This value becomes the chain for the next pass of the loop, and when the layer
finishes it becomes the starting table for the layer below.`,
  references: [],
};

const narrModulus: StepDocumentation = {
  name: "q = 3329",
  summary: "The prime everything is computed modulo. Editable — try it.",
  detail: `## Why this number

\`q = 3329\` is not a round number and not a machine word. Two facts about it are
load-bearing:

- **It is prime.** So every non-zero value has a multiplicative inverse, and the
  arithmetic below is a field.
- **q − 1 = 3328 = 2⁸ × 13.** A root of unity of order \`k\` exists modulo a
  prime \`q\` exactly when \`k\` divides \`q − 1\`. Since 256 divides 3328, a
  256th root exists — that is 17 — and the transform is possible at all. Since
  512 does not divide 3328, no 512th root exists, which is why the transform
  runs seven layers instead of eight.

## It arrives on a wire

Notice this value comes in on a port rather than sitting in a step's settings.
The modulus is a design decision here, not an implementation detail, so it is
something to look at and change.

**Try setting it to 3331** (also prime, but 3330 = 2 × 3 × 5 × 3 × 37 has only
one factor of 2). The arithmetic still runs perfectly — and the transform stops
being invertible, because there is no longer a 256th root of unity for the
twiddle factors to be powers of.`,
  references: ["FIPS 203 §2.4.4"],
};

const narrTwist: StepDocumentation = {
  name: "t = ζ · hi",
  summary: "Scales the high half by this group's twiddle factor. The twist itself.",
  detail: `## The one interesting operation in the layer

Everything else in this group is addition and subtraction. This is the step that
makes the transform a transform.

\`\`\`
t = ζ · hi   (every coefficient of the high half, times ζ)
\`\`\`

The two steps below then form \`lo + t\` and \`lo − t\`. Because ζ has order 256,
those two combinations carry enough information to be undone later — which is
what makes the whole thing invertible rather than merely a mixing function.

Products are formed at full width before reducing: two coefficients below 3329
multiply to as much as eleven million, and letting that overflow before reducing
gives a wrong answer that still looks like noise.`,
  references: ["FIPS 203 Algorithm 9"],
};

const narrForwardAdd: StepDocumentation = {
  name: "lo′ = lo + t",
  summary: "The sum half of the butterfly.",
  detail: `## Half of a two-line operation

\`\`\`
lo′ = lo + t
hi′ = lo − t     ← the next step
\`\`\`

Take a pair of numbers, produce their sum and their difference. Given both you
can recover the originals; given only one you cannot. That is the sense in which
this pair of steps rearranges information rather than destroying it, and it is
the same butterfly the FFT is built from — done in integers modulo a prime, so
there is no rounding anywhere and the inverse is exact.`,
  references: ["FIPS 203 Algorithm 9"],
};

const narrForwardSub: StepDocumentation = {
  name: "hi′ = lo − t",
  summary: "The difference half of the butterfly. Results below zero wrap up by q.",
  detail: `## The other half

\`\`\`
lo′ = lo + t     ← the previous step
hi′ = lo − t
\`\`\`

Note that both lines read the **original** \`lo\`, not the one the step above
just produced. In a hand-written implementation that is the classic place to go
wrong — overwrite \`lo\` first and \`hi′\` comes out as \`lo + 2t\`. Here the two
steps read the same wire, so the mistake is not expressible.

## Large numbers are small negative ones

There are no negative values in this system: \`3 − 5\` comes out as 3327, not
−2. They are the same element modulo 3329. Expect the output of this step to look
like large numbers — subtract 3329 in your head to see the small ones.`,
  references: ["FIPS 203 Algorithm 9"],
};

const narrInverseAdd: StepDocumentation = {
  name: "lo′ = lo + hi",
  summary: "The inverse butterfly combines first and twists afterwards.",
  detail: `## The inverse is not the forward run backwards

\`\`\`
forward:   t = ζ·hi ;  lo′ = lo + t ;  hi′ = lo − t
inverse:   lo′ = lo + hi ;  hi′ = ζ·(hi − lo)
\`\`\`

The forward butterfly multiplies **before** combining; this one combines
**after**. They are different shapes, not the same shape with a sign flipped —
the first is named after Cooley and Tukey, the second after Gentleman and Sande.

This step is the sum, and it needs no twiddle factor at all.`,
  references: ["FIPS 203 Algorithm 10"],
};

const narrInverseSub: StepDocumentation = {
  name: "hi − lo",
  summary: "The difference, before it is scaled by the twiddle factor.",
  detail: `## Difference first, twist second

\`\`\`
hi′ = ζ · (hi − lo)
        └─ this step ─┘
\`\`\`

Note the order of the operands: \`hi − lo\`, not \`lo − hi\`. Swapping them
negates the result, and since the twiddle multiply afterwards is linear, the
error survives all the way to the output — as a sign flip on half the
coefficients that no round-trip test would necessarily catch.`,
  references: ["FIPS 203 Algorithm 10"],
};

const narrInverseTwist: StepDocumentation = {
  name: "hi′ = ζ · (hi − lo)",
  summary: "Scales the difference by this group's twiddle factor.",
  detail: `## Undoing the twist

The forward transform multiplied the high half by ζ before combining. This
multiplies the recombined difference by ζ afterwards. Across seven layers the
two sets of multiplications cancel — up to one leftover factor of 128, which the
final scaling step at the bottom removes.`,
  references: ["FIPS 203 Algorithm 10"],
};

const narrRecombine: StepDocumentation = {
  name: "Rejoin the halves",
  summary: "Puts the two transformed halves back in place, low then high.",
  detail: `## Nothing moves

The two halves go back exactly where they came from — low half first, high half
second. Unlike a Feistel round, there is no swap hidden in this ordering; the
transform's rearrangement lives entirely in which coefficients get paired at each
layer, not in any reordering here.`,
  references: [],
};

const narrScale: StepDocumentation = {
  name: `Scale by 128⁻¹ = ${N_INV_128}`,
  summary: "The last step of the inverse: divide out the factor the layers accumulated.",
  detail: `## Why anything is left over at all

Each of the seven layers doubles the result, in the same way that an inverse FFT
comes out scaled by its length. Seven layers means a factor of 2⁷ = 128, so the
inverse finishes by multiplying every coefficient by \`128⁻¹ mod 3329\`, which is
**${N_INV_128}**. Check it: 128 × ${N_INV_128} = ${128 * N_INV_128}, and that is
${(128 * N_INV_128 - 1) / ML_KEM_Q} × 3329 + 1.

## 128, not 256

This is the single easiest thing to get wrong in the whole transform. There are
256 coefficients, so \`256⁻¹\` looks like the natural constant — but the
transform runs **seven** layers, not eight, because no primitive 512th root of
unity exists modulo 3329. Using \`256⁻¹ = 3316\` produces a perfectly
self-consistent transform whose every output is exactly half of what it should
be, and which agrees with no other implementation on earth.

**Try it.** Change this value to 3316 and compare against the original
polynomial.`,
  references: ["FIPS 203 Algorithm 10", "FIPS 203 §2.4.4"],
};

// ─── Layer bodies ─────────────────────────────────────────────────────────

/**
 * One forward layer's butterfly group. Runs once per group; the runtime hands
 * it this group's coefficients on `in` and the ζ cursor on `chain`.
 */
const forwardLayerBody = (g: LayerGeometry): StepNode[] => {
  const id = g.id;
  const half = g.blockBytes / 2;
  return [
    {
      kind: "step",
      id: `${id}.split`,
      type: "split-bytes@1",
      params: { widths: [half, half] },
      portInputs: { input: port(id, "in") },
      narrationOverride: narrLayerSplit(g),
    },
    {
      kind: "step",
      id: `${id}.zeta`,
      type: "split-bytes@1",
      params: { widths: [COEFF_BYTES, ZETA_TABLE_BYTES.length - COEFF_BYTES] },
      portInputs: { input: port(id, "chain") },
      narrationOverride: narrZetaRead(g),
    },
    {
      // Forced through aux: port flow cannot cross into an iterate body. See
      // the file header.
      kind: "step",
      id: `${id}.q`,
      type: "aux-load-bytes@1",
      params: { auxName: "q", byteLength: COEFF_BYTES },
      narrationOverride: narrModulus,
    },
    {
      kind: "step",
      id: `${id}.twist`,
      type: "zq-vec-mul-scalar@1",
      params: { ...VEC_PARAMS },
      portInputs: {
        a: port(`${id}.split`, "output1"),
        scalar: port(`${id}.zeta`, "output0"),
        modulus: port(`${id}.q`, "output"),
      },
      narrationOverride: narrTwist,
    },
    {
      kind: "step",
      id: `${id}.lo`,
      type: "zq-vec-add@1",
      params: { ...VEC_PARAMS },
      portInputs: {
        a: port(`${id}.split`, "output0"),
        b: port(`${id}.twist`, "output"),
        modulus: port(`${id}.q`, "output"),
      },
      narrationOverride: narrForwardAdd,
    },
    {
      // Reads the ORIGINAL low half, not `lo` above — see that step's prose.
      kind: "step",
      id: `${id}.hi`,
      type: "zq-vec-sub@1",
      params: { ...VEC_PARAMS },
      portInputs: {
        a: port(`${id}.split`, "output0"),
        b: port(`${id}.twist`, "output"),
        modulus: port(`${id}.q`, "output"),
      },
      narrationOverride: narrForwardSub,
    },
    {
      kind: "step",
      id: `${id}.out`,
      type: "concat@1",
      params: { inputCount: 2 },
      portInputs: {
        input0: port(`${id}.lo`, "output"),
        input1: port(`${id}.hi`, "output"),
      },
      narrationOverride: narrRecombine,
    },
    {
      // Rotate LEFT: the consumed factor goes to the back.
      kind: "step",
      id: `${id}.advance`,
      type: "concat@1",
      params: { inputCount: 2 },
      portInputs: {
        input0: port(`${id}.zeta`, "output1"),
        input1: port(`${id}.zeta`, "output0"),
      },
      narrationOverride: narrAdvance,
    },
  ];
};

/**
 * One inverse layer's butterfly group. Same skeleton, three differences: the
 * cursor is read off the BACK of the table (the inverse consumes ζ¹²⁷ down to
 * ζ¹), the rotation goes the other way, and the twiddle multiply happens after
 * the subtraction rather than before the addition.
 */
const inverseLayerBody = (g: LayerGeometry): StepNode[] => {
  const id = g.id;
  const half = g.blockBytes / 2;
  return [
    {
      kind: "step",
      id: `${id}.split`,
      type: "split-bytes@1",
      params: { widths: [half, half] },
      portInputs: { input: port(id, "in") },
      narrationOverride: narrLayerSplit(g),
    },
    {
      kind: "step",
      id: `${id}.zeta`,
      type: "split-bytes@1",
      // The cursor sits at the BACK here: output0 is the remaining table,
      // output1 is this group's ζ.
      params: { widths: [ZETA_TABLE_BYTES.length - COEFF_BYTES, COEFF_BYTES] },
      portInputs: { input: port(id, "chain") },
      narrationOverride: narrZetaRead(g),
    },
    {
      kind: "step",
      id: `${id}.q`,
      type: "aux-load-bytes@1",
      params: { auxName: "q", byteLength: COEFF_BYTES },
      narrationOverride: narrModulus,
    },
    {
      kind: "step",
      id: `${id}.lo`,
      type: "zq-vec-add@1",
      params: { ...VEC_PARAMS },
      portInputs: {
        a: port(`${id}.split`, "output0"),
        b: port(`${id}.split`, "output1"),
        modulus: port(`${id}.q`, "output"),
      },
      narrationOverride: narrInverseAdd,
    },
    {
      // `hi − lo`, in that order. Reversed, every high coefficient comes out
      // negated.
      kind: "step",
      id: `${id}.diff`,
      type: "zq-vec-sub@1",
      params: { ...VEC_PARAMS },
      portInputs: {
        a: port(`${id}.split`, "output1"),
        b: port(`${id}.split`, "output0"),
        modulus: port(`${id}.q`, "output"),
      },
      narrationOverride: narrInverseSub,
    },
    {
      kind: "step",
      id: `${id}.hi`,
      type: "zq-vec-mul-scalar@1",
      params: { ...VEC_PARAMS },
      portInputs: {
        a: port(`${id}.diff`, "output"),
        scalar: port(`${id}.zeta`, "output1"),
        modulus: port(`${id}.q`, "output"),
      },
      narrationOverride: narrInverseTwist,
    },
    {
      kind: "step",
      id: `${id}.out`,
      type: "concat@1",
      params: { inputCount: 2 },
      portInputs: {
        input0: port(`${id}.lo`, "output"),
        input1: port(`${id}.hi`, "output"),
      },
      narrationOverride: narrRecombine,
    },
    {
      // Rotate RIGHT: the consumed factor (at the back) moves to the front, so
      // the next group finds its predecessor at the back.
      kind: "step",
      id: `${id}.advance`,
      type: "concat@1",
      params: { inputCount: 2 },
      portInputs: {
        input0: port(`${id}.zeta`, "output1"),
        input1: port(`${id}.zeta`, "output0"),
      },
      narrationOverride: narrAdvance,
    },
  ];
};

// ─── The specs ────────────────────────────────────────────────────────────

const layerLabel = (g: LayerGeometry): string =>
  `Layer ${g.displayIndex} — ${g.groups} group${g.groups === 1 ? "" : "s"} of ${2 * g.len}, pairing distance ${g.len}`;

/**
 * The forward transform. Layers run with pairing distance 128 → 2, and the ζ
 * cursor is pre-rotated so the first group lands on ζ¹.
 */
export const buildNttSpec = (): CipherSpec => {
  const steps: StepNode[] = [
    {
      kind: "step",
      id: NTT_ZETA_TABLE_ID,
      type: "aux-load-bytes@1",
      params: { auxName: "zeta", byteLength: ZETA_TABLE_BYTES.length },
      narrationOverride: narrZetaTable,
    },
    {
      kind: "step",
      id: NTT_CURSOR_SPLIT_ID,
      type: "split-bytes@1",
      params: { widths: [COEFF_BYTES, ZETA_TABLE_BYTES.length - COEFF_BYTES] },
      portInputs: { input: port(NTT_ZETA_TABLE_ID, "output") },
      narrationOverride: narrCursorSplit,
    },
    {
      kind: "step",
      id: NTT_CURSOR_ID,
      type: "concat@1",
      params: { inputCount: 2 },
      portInputs: {
        input0: port(NTT_CURSOR_SPLIT_ID, "output1"),
        input1: port(NTT_CURSOR_SPLIT_ID, "output0"),
      },
      narrationOverride: narrCursor,
    },
  ];

  for (let n = 1; n <= NTT_LAYERS; n++) {
    // Forward: layer n has pairing distance 128 / 2^(n-1), so the widest group
    // comes first.
    const g = geometryFor(n, layerLen(n));
    steps.push({
      kind: "iterate",
      id: g.id,
      label: layerLabel(g),
      seedInput:
        n === 1 ? port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT) : port(nttLayerId(n - 1), "out"),
      blockByteLength: g.blockBytes,
      chainInput: n === 1 ? port(NTT_CURSOR_ID, "output") : port(nttLayerId(n - 1), CURSOR_PORT),
      chainFeedback: port(`${g.id}.advance`, "output"),
      chainOutput: CURSOR_PORT,
      bodyOutput: port(`${g.id}.out`, "output"),
      outputPorts: ["out"],
      children: forwardLayerBody(g),
    });
  }

  return {
    id: "ntt-3329-256@1",
    name: "NTT over Z_3329[X]/(X^256+1)",
    stateShape: "bytes",
    inputs: {
      // The polynomial is the message. No key — the transform is a change of
      // representation, not an encryption, so the key field is zero-width and
      // the UI hides it (the hash / PRNG / RSA posture).
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    cipherConstants: { q: Q_BYTES, zeta: ZETA_TABLE_BYTES },
    steps,
    outputFrom: port(nttLayerId(NTT_LAYERS), "out"),
  };
};

/**
 * The inverse transform. Layers run with pairing distance 2 → 128 (the opposite
 * order), the cursor is consumed from the back (ζ¹²⁷ down to ζ¹) so it takes
 * the published table unrotated, and a final `× 128⁻¹` removes the factor the
 * seven layers accumulate.
 */
export const buildInverseNttSpec = (): CipherSpec => {
  const steps: StepNode[] = [
    {
      kind: "step",
      id: NTT_ZETA_TABLE_ID,
      type: "aux-load-bytes@1",
      params: { auxName: "zeta", byteLength: ZETA_TABLE_BYTES.length },
      narrationOverride: narrZetaTable,
    },
  ];

  for (let n = 1; n <= NTT_LAYERS; n++) {
    // The inverse runs the layers in the OPPOSITE order: its layer 1 has the
    // smallest pairing distance (2), which is the forward layer 7's. Node ids
    // still key on `n` — the display index — so the spec reads top to bottom.
    const g = geometryFor(n, layerLen(NTT_LAYERS + 1 - n));
    steps.push({
      kind: "iterate",
      id: g.id,
      label: layerLabel(g),
      seedInput:
        n === 1 ? port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT) : port(nttLayerId(n - 1), "out"),
      blockByteLength: g.blockBytes,
      chainInput:
        n === 1 ? port(NTT_ZETA_TABLE_ID, "output") : port(nttLayerId(n - 1), CURSOR_PORT),
      chainFeedback: port(`${g.id}.advance`, "output"),
      chainOutput: CURSOR_PORT,
      bodyOutput: port(`${g.id}.out`, "output"),
      outputPorts: ["out"],
      children: inverseLayerBody(g),
    });
  }

  steps.push(
    {
      kind: "step",
      id: INTT_NINV_ID,
      type: "aux-load-bytes@1",
      params: { auxName: "ninv", byteLength: COEFF_BYTES },
      narrationOverride: narrScale,
    },
    {
      kind: "step",
      id: INTT_SCALE_Q_ID,
      type: "aux-load-bytes@1",
      params: { auxName: "q", byteLength: COEFF_BYTES },
      narrationOverride: narrModulus,
    },
    {
      kind: "step",
      id: INTT_SCALE_ID,
      type: "zq-vec-mul-scalar@1",
      params: { ...VEC_PARAMS },
      portInputs: {
        a: port(nttLayerId(NTT_LAYERS), "out"),
        scalar: port(INTT_NINV_ID, "output"),
        modulus: port(INTT_SCALE_Q_ID, "output"),
      },
      narrationOverride: narrScale,
    },
  );

  return {
    id: "ntt-3329-256-inverse@1",
    name: "Inverse NTT over Z_3329[X]/(X^256+1)",
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    cipherConstants: { q: Q_BYTES, zeta: ZETA_TABLE_BYTES, ninv: N_INV_BYTES },
    steps,
    outputFrom: port(INTT_SCALE_ID, "output"),
  };
};

/**
 * The default polynomial the app opens on: `f(X) = 0 + 1·X + 2·X² + …`, the
 * sequential house pattern AES and Serpent use, and every coefficient is safely
 * below q. It transforms to something with no visible structure, which is the
 * point of looking at it.
 */
export const DEFAULT_NTT_INPUT: Uint8Array = (() => {
  const out = new Uint8Array(POLY_BYTES);
  for (let i = 0; i < ML_KEM_N; i++) {
    out[i * COEFF_BYTES] = (i >>> 8) & 0xff;
    out[i * COEFF_BYTES + 1] = i & 0xff;
  }
  return out;
})();

/**
 * The forward transform of `DEFAULT_NTT_INPUT` — the inverse direction's
 * default input, so landing in "inverse" mode and running gives the sequential
 * coefficients straight back. The decrypt-side analogue of
 * `DEFAULT_CT_BYTES_BY_CIPHER`.
 *
 * **Not hand-derived, and not produced by the spec it is a default for.** These
 * bytes come from evaluating FIPS 203 §2.4.4's definition directly — the same
 * double loop `tests/ntt-3329-256-kat.test.ts` uses as its rank-1 oracle — so
 * pinning them against a real run (which that test does) is a genuine check
 * rather than a tautology.
 *
 * Stored as hex because 512 bytes of `0x..` literals is a page of noise.
 */
export const DEFAULT_NTT_OUTPUT: Uint8Array = (() => {
  const hex =
    "097d0b1d01a9031b0749054c0270001f09b308950aa50a6c0a93020505d0089207b30323039a" +
    "00e7090f02650433025e01320c4705640a9e04830213033206320b3a009b013005a20a3b06b0" +
    "0879086f05c70a4a0b3007de068f0c80006607830643022e02a9013c020503a306c407cf07e8" +
    "044608e4086f088b07b50a4d086e094500c60baa00f705ca01c10485050a042108ac046403fb" +
    "0190089e04c908b905600b400a68026607a807b60b760a770b2c08a90b510ca2077100240902" +
    "086100db02450bb8056209580b1306950443041e0866021f0c7809d60cae08e5023a00ef09da" +
    "034607c6007e0a4d007e03320ca0043303ac02e60a390276028a0ad80a2e01e208a00364079d" +
    "08650bfa07680bb40902003f0373099f0521079f0bb70061070e0b0e083806eb099501720a2d" +
    "036705bb097a07c1093b029203f7028f01f5029804e10c30006a0c1c04fa077f0762086307a9" +
    "079d06ca01cd0ad404f60c170829041b0a10065c06c70c7b07f2028f020c0c7b038507d7058b" +
    "009d091e09280b09027a035209db0a5202a0064400d80cd005250389048d05fc0bf3030900f2" +
    "06d80804021503ee07420920049f0678068407f50b820888041800680b09036d006f055307c5" +
    "07cb0293000c01fa060f07e60c8c06370665091a06590aeb0306004603ea0c7a03a003db0a9d" +
    "0bbd0b4300950a220c2109c608560a9d08ff";
  const out = new Uint8Array(POLY_BYTES);
  for (let i = 0; i < POLY_BYTES; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
})();
