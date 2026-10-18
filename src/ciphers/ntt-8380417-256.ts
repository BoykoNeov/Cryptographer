/**
 * The number-theoretic transform over `R_q = Z_q[X]/(X²⁵⁶+1)`, `q = 8380417` —
 * the arithmetic engine underneath ML-DSA, and the lattice category's second
 * member. `docs/plans/refactored-petting-tide.md`, P1.
 *
 * ## The same machine with a different prime in it
 *
 * This file contains no transform logic. It hands `ntt-3329-256.ts`'s builder a
 * different `NttProfile` — eight layers instead of seven, four-byte coefficients
 * instead of two, a 1024-byte ζ table instead of 256 — and its own prose. The
 * butterflies, the rotating ζ cursor riding each layer's chain, `q` reaching the
 * body through aux: all of it is the object the ML-KEM NTT entry already shows.
 * That is deliberate. The interesting difference between the two transforms is
 * not in the algorithm but in the prime, and a learner can only see that if
 * everything else is held still.
 *
 * ## Eight layers, and why this prime allows them
 *
 * ```
 *   layer 1:    1 group  of 256 coefficients   (block 1024 bytes)
 *   layer 2:    2 groups of 128                (block  512)
 *   …
 *   layer 7:   64 groups of   4                (block   16)
 *   layer 8:  128 groups of   2                (block    8)
 *              ───
 *             255 groups total, one twiddle factor each
 * ```
 *
 * `q − 1 = 2¹³ · 3 · 11 · 31` has thirteen factors of 2, so a primitive 512th
 * root of unity exists (1753) and the last split — the one ML-KEM cannot make —
 * goes through. The output is 256 independent values rather than 128 degree-1
 * pairs, and the inverse scales by `256⁻¹` rather than `128⁻¹`.
 *
 * ## Inside ML-DSA, this is one frame
 *
 * One ML-DSA signing attempt runs 21 of these transforms. Fully traced, that is
 * ~38,000 frames an attempt and ~160,000 a signature, so ML-DSA's specs call a
 * one-frame `ml-dsa.ntt@1` that points back here (the plan's decision 2 — the
 * same cross-reference ML-KEM makes for its Keccak calls). This entry is where
 * the transform is shown in full.
 *
 * ## Verification
 *
 * `tests/ntt-8380417-256-kat.test.ts`, strongest first: evaluation against the
 * transform's definition (an independent double loop), the convolution theorem
 * with an ELEMENT-WISE product (correct here, wrong for ML-KEM), the published ζ
 * table, and the round trip last.
 */

import type { CipherSpec, StepDocumentation } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { port } from "./block-cipher-core";
import {
  ML_DSA_COEFF_BYTES,
  ML_DSA_N,
  ML_DSA_NTT_LAYERS,
  ML_DSA_N_INV_256,
  ML_DSA_N_INV_BYTES,
  ML_DSA_POLY_BYTES,
  ML_DSA_Q,
  ML_DSA_Q_BYTES,
  ML_DSA_ZETAS,
  ML_DSA_ZETA_TABLE_BYTES,
} from "./mldsa-constants";
import {
  INTT_SCALE_ID,
  type LayerGeometry,
  type NttProfile,
  buildNttNodes,
  narrForwardAdd,
  narrInverseAdd,
  narrInverseSub,
  narrRecombine,
  nttLayerId,
} from "./ntt-3329-256";

// ─── Narration ────────────────────────────────────────────────────────────
//
// Only the prose that quotes a number is rewritten; the butterfly's sum,
// difference and rejoin read the same for any prime and are shared.

const narrZetaTable: StepDocumentation = {
  name: "The 256 twiddle factors",
  summary: "Powers of 1753 — the table of roots of unity every layer draws from.",
  detail: `## The numbers that make the transform work

All 256 twiddle factors, fetched as one 1024-byte table.

Every entry is a power of **1753**, and 1753 is special modulo 8380417: raise it
to the 256th power and you get 8380416, which is −1 here; raise it to the 512th
and you get 1. A number that returns to 1 after exactly 512 steps is what lets a
256-coefficient polynomial be split **all the way down** to 256 single values.

Compare the ML-KEM transform under the same menu: its root, 17, only has order
256, so its transform has to stop one layer earlier.

## They are not in the order you would guess

Entry \`k\` is \`1753\` raised to the power **bit-reverse-8 of k**:

\`\`\`
ZETAS[1] = 1753^128 = 4808194
ZETAS[2] = 1753^64  = 3765607
ZETAS[3] = 1753^192 = 3761513
\`\`\`

That scrambled order is exactly the order the layers consume them in — one per
butterfly group, first to last — which is why the table can simply advance by
one entry each time instead of computing an address.

Entry 0 is listed as 0 rather than 1753⁰ = 1, because nothing ever reads it.

Published as FIPS 204, Appendix B.`,
  references: ["FIPS 204 Appendix B — the ζ table", "FIPS 204 Algorithm 41 — NTT"],
};

const narrCursorSplit: StepDocumentation = {
  name: "Set the cursor to entry 1",
  summary: "Takes the unused entry 0 off the front so the first layer starts on 1753¹²⁸.",
  detail: `## Skipping the first entry

The transform never uses entry 0 of the table. The first butterfly group wants
entry 1.

This step and the one below it move that leading entry to the back, leaving the
cursor parked where the first layer needs it. From here on, every group takes
whatever is at the front and rotates the table by one.`,
  references: [],
};

const narrCursor: StepDocumentation = {
  name: "The rotating table",
  summary: "Entry 1 first, entry 0 moved to the back — the cursor the eight layers share.",
  detail: `## One table, 255 consumers

This 1024-byte value is handed to layer 1 and then passed from layer to layer,
each one leaving it advanced by however many groups it ran. Layer 1 runs one
group; layer 2 runs two; layer 8 runs 128. One plus two plus four … plus 128 is
255, and by the end all 255 have been used, in order, exactly once.

This is the same wire that carries CBC's chaining value and OFB's keystream
register. Nothing was added to the runtime to make the transform work.`,
  references: [],
};

const narrLayerSplit = (g: LayerGeometry): StepDocumentation => ({
  name: `Split into halves of ${g.len}`,
  summary: `Cuts this group's ${g.len * 2} coefficients into a low half and a high half.`,
  detail: `## The pairing

Layer ${g.displayIndex} pairs coefficient \`j\` with coefficient \`j + ${g.len}\`.
Cutting the group in half is how that pairing is expressed: everything in the low
half meets the element at the same position in the high half.

The pairing distance halves at every layer, running ${ML_DSA_N / 2} … 1 in the
forward direction and 1 … ${ML_DSA_N / 2} in the inverse. **Distance 1 is the
layer ML-KEM cannot run** — there, every group is just two neighbouring
coefficients, and after it each coefficient stands alone.`,
  references: ["FIPS 204 Algorithm 41"],
});

const narrZetaRead = (g: LayerGeometry): StepDocumentation => ({
  name: "Take this group's ζ",
  summary: "Reads this group's twiddle factor off the table; the rest is what remains.",
  detail: `## Four bytes off the end

Four bytes of the rotating table are this group's twiddle factor. The other 1020
are handed to the step that rotates them round.

Layer ${g.displayIndex} runs ${g.groups} group${g.groups === 1 ? "" : "s"}, so it
consumes ${g.groups} of the 255 factors before passing the table on.

**Scrub through the groups and watch this value change.** It is the only thing
that distinguishes one butterfly from another.`,
  references: [],
});

const narrAdvance: StepDocumentation = {
  name: "Advance the cursor",
  summary: "Moves the used factor to the back, so the next group finds the next one in front.",
  detail: `## Rotate by one entry

The factor just consumed goes to the back of the table and everything else moves
up four bytes. That is all "get the next twiddle factor" means here — no counter,
no index arithmetic, no lookup.`,
  references: [],
};

const narrModulus: StepDocumentation = {
  name: `q = ${ML_DSA_Q}`,
  summary: "The prime everything is computed modulo. Editable — try it.",
  detail: `## Why this number

\`q = 8380417 = 2²³ − 2¹³ + 1\`. Two facts about it are load-bearing:

- **It is prime**, so every non-zero value has an inverse.
- **q − 1 = 2¹³ × 3 × 11 × 31.** A root of unity of order \`k\` exists exactly
  when \`k\` divides \`q − 1\`. Thirteen factors of two means a 512th root exists
  — that is 1753 — and the transform can run all eight layers.

ML-KEM's prime, 3329, has \`q − 1 = 2⁸ × 13\`: eight factors of two, one short of
what an eighth layer needs. That single difference is why the two NTTs in this
menu have different depths.

## It arrives on a wire

The modulus is a design decision here, not an implementation detail, so it is
something to look at and change.`,
  references: ["FIPS 204 §2.3"],
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

## A product too big for an ordinary number

Two coefficients below 8380417 multiply to as much as **70 trillion** — a
46-bit number, though each coefficient fits in 23 bits. A product held in a
32-bit integer would silently lose its top bits before it was reduced, and the
answer would be wrong in a way that still looks like noise. The step forms the
full product and reduces afterwards; the reference C implementation multiplies
in 64 bits and reduces with Montgomery's trick for the same reason.`,
  references: ["FIPS 204 Algorithm 41"],
};

const narrForwardSub: StepDocumentation = {
  name: "hi′ = lo − t",
  summary: "The difference half of the butterfly. Results below zero wrap up by q.",
  detail: `## The other half

\`\`\`
lo′ = lo + t     ← the previous step
hi′ = lo − t
\`\`\`

Both lines read the **original** \`lo\`, not the one the step above just
produced. Overwrite \`lo\` first and \`hi′\` comes out as \`lo + 2t\` — here the two
steps read the same wire, so the mistake is not expressible.

## Large numbers are small negative ones

There are no negative values in this system: \`3 − 5\` comes out as 8380415, not
−2. They are the same element modulo 8380417.`,
  references: ["FIPS 204 Algorithm 41"],
};

const narrInverseTwist: StepDocumentation = {
  name: "hi′ = ζ · (hi − lo)",
  summary: "Scales the difference by this group's twiddle factor.",
  detail: `## Undoing the twist

The forward transform multiplied the high half by ζ before combining. This
multiplies the recombined difference by ζ afterwards. Across eight layers the
two sets of multiplications cancel — up to one leftover factor of 256, which the
final scaling step at the bottom removes.

FIPS 204 writes this line as \`−ζ · (lo − hi)\`. It is the same number.`,
  references: ["FIPS 204 Algorithm 42"],
};

const narrScale: StepDocumentation = {
  name: `Scale by 256⁻¹ = ${ML_DSA_N_INV_256}`,
  summary: "The last step of the inverse: divide out the factor the layers accumulated.",
  detail: `## Why anything is left over at all

Each of the eight layers doubles the result, the same way an inverse FFT comes
out scaled by its length. Eight layers means a factor of 2⁸ = 256, so the
inverse finishes by multiplying every coefficient by \`256⁻¹ mod 8380417\`,
which is **${ML_DSA_N_INV_256}**. Check it: 256 × ${ML_DSA_N_INV_256} =
${256 * ML_DSA_N_INV_256}, which is ${(256 * ML_DSA_N_INV_256 - 1) / ML_DSA_Q} × 8380417 + 1.

## 256 here, 128 for ML-KEM

The ML-KEM transform in this menu ends by scaling by \`128⁻¹\`, because it runs
only seven layers. Here, with all eight, \`256⁻¹\` is right. The constant is not a
property of "an NTT on 256 coefficients" — it is a property of how many layers
the prime allowed.`,
  references: ["FIPS 204 Algorithm 42"],
};

// ─── The profile ──────────────────────────────────────────────────────────

/** ML-DSA's transform: eight layers over q = 8380417, four bytes a coefficient. */
export const ML_DSA_NTT_PROFILE: NttProfile = {
  n: ML_DSA_N,
  layers: ML_DSA_NTT_LAYERS,
  coeffBytes: ML_DSA_COEFF_BYTES,
  zetaTableBytes: ML_DSA_ZETA_TABLE_BYTES.length,
  narration: {
    zetaTable: narrZetaTable,
    cursorSplit: narrCursorSplit,
    cursor: narrCursor,
    layerSplit: narrLayerSplit,
    zetaRead: narrZetaRead,
    advance: narrAdvance,
    modulus: narrModulus,
    twist: narrTwist,
    forwardAdd: narrForwardAdd,
    forwardSub: narrForwardSub,
    inverseAdd: narrInverseAdd,
    inverseSub: narrInverseSub,
    inverseTwist: narrInverseTwist,
    recombine: narrRecombine,
    scale: narrScale,
  },
};

// ─── The specs ────────────────────────────────────────────────────────────

/** The forward transform. Layers run with pairing distance 128 → 1. */
export const buildMlDsaNttSpec = (): CipherSpec => {
  const { nodes } = buildNttNodes({
    direction: "forward",
    seedBinding: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
    profile: ML_DSA_NTT_PROFILE,
  });
  return {
    id: "ntt-8380417-256@1",
    name: "NTT over Z_8380417[X]/(X^256+1)",
    stateShape: "bytes",
    inputs: {
      // No key: the transform is a change of representation, not an encryption.
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    cipherConstants: { q: ML_DSA_Q_BYTES, zeta: ML_DSA_ZETA_TABLE_BYTES },
    steps: [...nodes],
    outputFrom: port(nttLayerId(ML_DSA_NTT_LAYERS), "out"),
  };
};

/**
 * The inverse transform. Layers run with pairing distance 1 → 128, the cursor is
 * consumed from the back (entry 255 down to entry 1), and a final `× 256⁻¹`
 * removes the factor the eight layers accumulate.
 */
export const buildMlDsaInverseNttSpec = (): CipherSpec => {
  const { nodes } = buildNttNodes({
    direction: "inverse",
    seedBinding: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
    profile: ML_DSA_NTT_PROFILE,
  });
  return {
    id: "ntt-8380417-256-inverse@1",
    name: "Inverse NTT over Z_8380417[X]/(X^256+1)",
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    cipherConstants: {
      q: ML_DSA_Q_BYTES,
      zeta: ML_DSA_ZETA_TABLE_BYTES,
      ninv: ML_DSA_N_INV_BYTES,
    },
    steps: [...nodes],
    outputFrom: port(INTT_SCALE_ID, "output"),
  };
};

/** Re-exported so callers reading the table do not need the constants module. */
export { ML_DSA_ZETAS };

/**
 * The default polynomial: `f(X) = 0 + 1·X + 2·X² + … + 255·X²⁵⁵`, the same
 * sequential pattern the ML-KEM transform opens on, at four bytes a coefficient.
 */
export const DEFAULT_ML_DSA_NTT_INPUT: Uint8Array = (() => {
  const out = new Uint8Array(ML_DSA_POLY_BYTES);
  for (let i = 0; i < ML_DSA_N; i++) {
    out[i * ML_DSA_COEFF_BYTES + 2] = (i >>> 8) & 0xff;
    out[i * ML_DSA_COEFF_BYTES + 3] = i & 0xff;
  }
  return out;
})();

/**
 * The forward transform of `DEFAULT_ML_DSA_NTT_INPUT` — the inverse direction's
 * default input, so landing in "inverse" and running gives 0, 1, 2, … back.
 *
 * **Not produced by the spec it is a default for.** These bytes come from
 * evaluating the definition directly — `f(1753^(2·BitRev8(j)+1))` for each `j`,
 * the double loop `tests/ntt-8380417-256-kat.test.ts` uses as its rank-1 oracle
 * — and were cross-checked against a straight transcription of FIPS 204
 * Algorithm 41 when generated. Pinning them against a real run is therefore a
 * genuine check rather than a tautology.
 */
export const DEFAULT_ML_DSA_NTT_OUTPUT: Uint8Array = (() => {
  const hex =
    "007a6f0f004b87b60053fad1006e487e003e366c000dc9250022e6090033b7d300161800003b" +
    "b163003a7d40005167f100798d85007be2cd006d05f10071d5c8007d20d500563b3700591f39" +
    "000007f9007f175100230aa300745664007668d4006411d60025956b000909200073e8ad0007" +
    "7bda0045bd3200082a51005a1d2e0022a083000064700000feff005c68980006addf0052f9b1" +
    "0000b09900375e7e005a8498004aa574004323f8003217a7005521cc001f216b007c0b11003c" +
    "aacf000d86e300507ed5001a2caf0024f5610007af6600262700003507a4002081ab00750fc7" +
    "00759906005e75e7001ca4d7001cafde006ffea9004f395b00710c09003dbeaa00640591000d" +
    "2580004ffbc60033256100799341007dbdb8002c631b0010714b006bdb7200103a98001fc55d" +
    "0012b912004acb2a005dcf660044ea6e0076c946004ae7d70025fe60007aec39001b938a002f" +
    "ee9a00403dc900258ca70061badd005c6684000aadce007c465600028ff5002af50d0050ffaa" +
    "007708b7006f69e6002b386a005efae0004099be003ccc42006a58e0006d9c8e005d9521002e" +
    "d82100726f220054d49c006f896e00527a97004d5a110032a984002567e6002e6fab002ed9f7" +
    "003c875e005f4848001fcc1f00215b4a0078ce31005775ba007f84f5004941f400348ec30062" +
    "4ef9002ff2ae00446813003e07ea001e508f007faf9b00466ded000234b0003fc05f0029a45c" +
    "006c9e330012afc2002d77500028e2880027fb880031b25200714eeb00449a180060dfc50069" +
    "631a0045c1b10052e3c30043646400326a7c0055194500306dd9005c82b8007d454d001219f4" +
    "002ef3270077a4cb002bdd97001eb9b0004a962e005495c5005dd53d006b6379002942200002" +
    "447b0011fb280053d4ca002bd05a002489ef00450ae000098de6007c2cdc001ed54d002cb813" +
    "0069f3330032512c00327f0300796d2b00353f2b0010cf590021917e0028b5db0004c06f0046" +
    "6ef30004185c00780e4c0011c6e2005f5013007920c200346e64004ddb1600134bee005bdf95" +
    "003268840001966e0003d91000620e1d003d0359000e052b004156b90029e983001399f90056" +
    "3c06006acb1b001bbc1200080ffc00268ad9004d7f52007a1cf20020337b001f533200025ea9" +
    "0038bd4e0058234000695d080053e808006eb386005c451a00611040000df7f2000154bc0013" +
    "8ea80037a7a5007f9f930034aad9005ebe1d001b1bef001139ab0069834d003f5e93000f8a3f" +
    "006040e6000eff8900366052001395c90018b194001219ad000032d0000b96fa0061fb370050" +
    "c2aa002591480070ba7b006f065500147fb70013dae5000eec29003b921f0002f5c2004eee32" +
    "0015d02e002502c000010b930039a2f1006badbe0064073f000efbcb007b36b90032089b";
  const out = new Uint8Array(ML_DSA_POLY_BYTES);
  for (let i = 0; i < ML_DSA_POLY_BYTES; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
})();
