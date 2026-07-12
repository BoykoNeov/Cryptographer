/**
 * Twofish spec builder (Schneier et al. 1998) — the sixth cipher family and the
 * third Feistel after DES and Blowfish.
 *
 * `buildTwofishSpec(direction)` constructs the encrypt or decrypt spec out of
 * port-native primitives. Everything travels the ports as BIG-ENDIAN 32-bit
 * words (so the generic `add-mod-32@1` / `rotate-bits-right@1` primitives apply
 * unchanged); the LE↔BE crossing Twofish's little-endian serialization implies
 * is localized to two visible `permute@1` word-reversals at plaintext-in /
 * ciphertext-out. See `twofish-constants.ts` for the verified math oracle.
 *
 * ## Structure
 *
 * 1. **Key setup** (default-collapsed group). Twofish's partial-visibility
 *    split: the opaque `twofish.h-expand@1` monolith runs the h-function
 *    machinery (RS S-vector + key-dependent S-box construction + 40 h evals),
 *    publishing the A/B intermediates + `aux[twofish.S0..S3]`. Then 20 VISIBLE
 *    pseudo-Hadamard-transform (PHT) blocks combine the A_i/B_i into the 40
 *    subkeys, gathered by `twofish.publish-subkeys@1` into `aux[twofish.K.*]`.
 *
 * 2. **Input whitening** — reverse each plaintext word (LE→BE), split into
 *    R0..R3, XOR with the whitening subkeys, recombine → round-0 input.
 *
 * 3. **16 rounds** (port-mode groups). Each computes `T0 = g(R0)`,
 *    `T1 = g(ROL(R1,8))`, the PHT-in-F combine with two round subkeys, and the
 *    1-bit-rotation Feistel mix; the swap IS the recombine's `concat` order.
 *
 * 4. **Output whitening** — undo the final swap, XOR the output whitening
 *    subkeys, reverse each word (BE→LE) → ciphertext.
 *
 * ## Direction parameterization
 *
 * Encrypt and decrypt run the same network with the rotations inverted, the
 * round order + subkey consumption reversed, and the whitening subkeys swapped
 * (K0..3 ↔ K4..7). One builder, two specs (Speck / Blowfish precedent).
 */

import type { CipherSpec, PortBinding, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { TWOFISH_MDS, TWOFISH_MDS_POLY, TWOFISH_ROUNDS } from "./twofish-constants";

export type TwofishDirection = "encrypt" | "decrypt";

// ─── narrationOverride docs (Twofish-friendly names for the generic leaves) ──
// The round + key-schedule bodies reuse GENERIC primitives (split-bytes / xor /
// add-mod-32 / rotate-bits-right / concat / permute / gf-matrix-multiply@2) that
// would otherwise render with their generic names in the inspector. These
// overrides name the Twofish role each leaf plays (the DES/Blowfish precedent).
// Shared static docs per role; the few that need an index take function form.

const NARR_ROUND_SPLIT: StepDocumentation = {
  name: "Split into R0..R3",
  summary: "Split the 16-byte round input into the four 32-bit words R0, R1, R2, R3.",
  detail: `## Split into R0 ‖ R1 ‖ R2 ‖ R3

Each round works on four 32-bit words. R0 and R1 drive the g functions; R2 and
R3 are the halves the round mixes and rotates. The words then swap at the end
(which is just the recombine's argument order).`,
};

const NARR_G_SPLIT: StepDocumentation = {
  name: "Split into bytes",
  summary: "Split the g-function input word into its four bytes for S-box lookup.",
  detail: `## g: split into four bytes

g substitutes each byte of its 32-bit input through a different S-box, so the
word splits into four bytes. (Stored big-endian, they are read least-significant
first into S0..S3.)`,
};

const narrGSbox = (k: number): StepDocumentation => ({
  name: `S${k} lookup`,
  summary: `Substitute byte x${k} through the key-dependent S-box S${k}.`,
  detail: `## g: S${k}[x${k}]

The ${k === 0 ? "first" : k === 1 ? "second" : k === 2 ? "third" : "fourth"} of
g's four byte→byte substitutions, through the key-dependent S-box **S${k}**. All
four results feed the MDS matrix.`,
});

const NARR_G_CONCAT: StepDocumentation = {
  name: "Gather S-box outputs",
  summary: "Concatenate the four substituted bytes into the MDS input vector.",
  detail: `## g: gather the four S-box outputs

The four substituted bytes \`(S0[x0], S1[x1], S2[x2], S3[x3])\` become the
4-byte vector the MDS matrix multiplies.`,
};

const NARR_G_MDS: StepDocumentation = {
  name: "MDS multiply",
  summary: "Multiply the four substituted bytes by the MDS matrix (GF(2⁸)/0x169).",
  detail: `## g: MDS matrix

The maximum-distance-separable matrix over GF(2⁸)/0x169 spreads each of the four
substituted bytes across the whole 32-bit output — a single input-byte change
alters all four output bytes. This is g's diffusion.`,
};

const NARR_G_PERM: StepDocumentation = {
  name: "g output word",
  summary: "Reorder the MDS output bytes into the g-function's 32-bit result.",
  detail: `## g: the output word

The MDS output bytes are reordered into the 32-bit word g returns (Twofish's
little-endian byte convention crossing back to this explorer's big-endian
word ports).`,
};

const NARR_ROL_R1: StepDocumentation = {
  name: "ROL(R1, 8)",
  summary: "Rotate R1 left by 8 bits before its g function.",
  detail: `## ROL(R1, 8)

The second g input is R1 rotated left 8 bits — the asymmetry between the two g
inputs (\`g(R0)\` vs \`g(ROL(R1,8))\`) that breaks the round's symmetry.`,
};

const narrLoadK = (idx: number): StepDocumentation => ({
  name: `Load K[${idx}]`,
  summary: `Load round subkey K[${idx}] from the key schedule.`,
  detail: `## Load subkey K[${idx}]

One of this round's two subkeys, read from the aux material the key schedule
published. The two subkeys enter through the pseudo-Hadamard-transform combine
below.`,
});

const NARR_F0: StepDocumentation = {
  name: "F0 = T0 + T1 + K",
  summary: "Pseudo-Hadamard combine: F0 = (T0 + T1 + subkey) mod 2³².",
  detail: `## F0 = (T0 + T1 + K_{2r+8}) mod 2³²

The first output of the round's pseudo-Hadamard transform (PHT) combines the two
g outputs and the first round subkey. F0 is XORed into R2.`,
};

const NARR_DBL_T1: StepDocumentation = {
  name: "2·T1",
  summary: "Double the second g output (T1 + T1) for the PHT.",
  detail: `## 2·T1

The PHT's second output weights T1 twice, computed as \`T1 + T1\` mod 2³² (a
doubling, NOT a GF multiply).`,
};

const NARR_F1: StepDocumentation = {
  name: "F1 = T0 + 2·T1 + K",
  summary: "Pseudo-Hadamard combine: F1 = (T0 + 2·T1 + subkey) mod 2³².",
  detail: `## F1 = (T0 + 2·T1 + K_{2r+9}) mod 2³²

The second PHT output combines T0, twice T1, and the second round subkey. F1 is
XORed into the rotated R3.`,
};

const NARR_R2_XOR: StepDocumentation = {
  name: "R2 ⊕ F0",
  summary: "XOR F0 into R2 (before its 1-bit rotation).",
  detail: `## R2 ⊕ F0

The Feistel mix into R2: XOR the first PHT output F0. Encrypt then rotates the
result right by 1 bit; decrypt inverts the order.`,
};

const NARR_R2_ROT: StepDocumentation = {
  name: "ROR(·, 1)",
  summary: "Rotate the mixed R2 right by 1 bit.",
  detail: `## ROR(R2 ⊕ F0, 1)

Twofish's 1-bit round rotation on the R2 side. It thwarts certain
byte-alignment attacks by breaking word boundaries every round.`,
};

const NARR_R3_ROT: StepDocumentation = {
  name: "ROL(R3, 1)",
  summary: "Rotate R3 left by 1 bit (before XOR with F1).",
  detail: `## ROL(R3, 1)

The R3 side rotates left by 1 bit BEFORE the F1 XOR (encrypt); this
pre-rotation, paired with R2's post-rotation, is the round's rotation
asymmetry.`,
};

const NARR_R3_XOR: StepDocumentation = {
  name: "⊕ F1",
  summary: "XOR the second PHT output F1 into the rotated R3.",
  detail: `## (ROL(R3,1)) ⊕ F1

Complete the Feistel mix into R3 by XORing the second PHT output F1.`,
};

const NARR_RECOMBINE: StepDocumentation = {
  name: "Swap → (R2', R3', R0, R1)",
  summary: "Recombine with the halves swapped — the Feistel exchange.",
  detail: `## Swap and recombine

The next round's input is \`(R2', R3', R0, R1)\`: the mixed/rotated words become
the new R0/R1, and the old R0/R1 pass through as the new R2/R3. **The swap is
nothing more than this concatenation order** — Twofish, like every Feistel
cipher here, needs no dedicated swap step.`,
};

// Key-schedule PHT block narrators.
const narrLoadA = (i: number): StepDocumentation => ({
  name: `Load A[${i}]`,
  summary: `Load the h-output A[${i}] published by the opaque half.`,
  detail: `## Load A[${i}]

One of the 20 A-side h outputs the opaque \`h-expand\` step published. The PHT
below combines it with B[${i}] into two subkeys.`,
});

const narrLoadB = (i: number): StepDocumentation => ({
  name: `Load B[${i}]`,
  summary: `Load the h-output B[${i}] (already ROL 8) published by the opaque half.`,
  detail: `## Load B[${i}]

One of the 20 B-side h outputs (already rotated left 8 bits). Combined with
A[${i}] in the PHT below.`,
});

const narrPhtK0 = (i: number): StepDocumentation => ({
  name: `K[${2 * i}] = A + B`,
  summary: `PHT: K[${2 * i}] = (A[${i}] + B[${i}]) mod 2³².`,
  detail: `## PHT: K[${2 * i}] = (A[${i}] + B[${i}]) mod 2³²

The first pseudo-Hadamard-transform output — the even subkey is simply the sum
of the two h outputs, mod 2³².`,
});

const narrPhtDblB = (i: number): StepDocumentation => ({
  name: `2·B[${i}]`,
  summary: `Double B[${i}] (B + B) for the odd subkey.`,
  detail: `## 2·B[${i}]

The odd subkey weights B twice; this is the \`B + B\` doubling mod 2³².`,
});

const narrPhtT = (i: number): StepDocumentation => ({
  name: `A[${i}] + 2·B[${i}]`,
  summary: `Sum A[${i}] + 2·B[${i}] (before the 9-bit rotation).`,
  detail: `## A[${i}] + 2·B[${i}]

The pre-rotation value of the odd subkey — the PHT's second combination.`,
});

const narrPhtK1 = (i: number): StepDocumentation => ({
  name: `K[${2 * i + 1}] = ROL(A + 2B, 9)`,
  summary: `PHT: K[${2 * i + 1}] = ROL((A[${i}] + 2·B[${i}]), 9).`,
  detail: `## PHT: K[${2 * i + 1}] = ROL(A[${i}] + 2·B[${i}], 9)

The odd subkey — the second PHT combination, rotated left 9 bits. Together with
K[${2 * i}] this PHT block produces two of the 40 subkeys.`,
});

// Whitening narrators.
const NARR_IN_PERMUTE: StepDocumentation = {
  name: "Plaintext → words (LE→BE)",
  summary: "Reverse each 4-byte word of the plaintext (little-endian → big-endian).",
  detail: `## Plaintext byte order

Twofish reads the plaintext as four little-endian words. This step reverses each
word's four bytes so the rest of the cipher can work big-endian — teaching
Twofish's little-endian serialization honestly, at one visible spot.`,
};

const NARR_IN_SPLIT: StepDocumentation = {
  name: "Split into P0..P3",
  summary: "Split the byte-ordered plaintext into four 32-bit words.",
  detail: `## Split into P0 ‖ P1 ‖ P2 ‖ P3

The four plaintext words, about to be whitened by XOR with the input-whitening
subkeys K0..K3.`,
};

const narrInWhiten = (kIdx: number): StepDocumentation => ({
  name: `⊕ K[${kIdx}] (input whitening)`,
  summary: `XOR input-whitening subkey K[${kIdx}] into a plaintext word.`,
  detail: `## Input whitening: ⊕ K[${kIdx}]

Before round 0, each plaintext word is XORed with a whitening subkey. This
pre-whitening hides the round input from an attacker who knows only the
plaintext.`,
});

const NARR_IN_CONCAT: StepDocumentation = {
  name: "Round-0 input",
  summary: "Concatenate the whitened words into the round-0 input block.",
  detail: `## Round-0 input

The four whitened words join into the 16-byte block the first round consumes.`,
};

const NARR_OUT_SPLIT: StepDocumentation = {
  name: "Split final state",
  summary: "Split the last round's output into four words for output whitening.",
  detail: `## Split the final state

The round-16 output splits into four words. Output whitening also undoes the
last Feistel swap by re-indexing which word each output takes.`,
};

const narrOutWhiten = (kIdx: number): StepDocumentation => ({
  name: `⊕ K[${kIdx}] (output whitening)`,
  summary: `XOR output-whitening subkey K[${kIdx}] into a final word.`,
  detail: `## Output whitening: ⊕ K[${kIdx}]

After the last round, each output word is XORed with a whitening subkey
(K4..K7). Combined with the swap-undo, this produces the ciphertext words.`,
});

const NARR_OUT_CONCAT: StepDocumentation = {
  name: "Ciphertext words",
  summary: "Concatenate the whitened output words.",
  detail: `## Whitened output words

The four output-whitened words join before the final byte-order reversal.`,
};

const NARR_OUT_PERMUTE: StepDocumentation = {
  name: "Words → ciphertext (BE→LE)",
  summary: "Reverse each word's bytes back to Twofish's little-endian ciphertext.",
  detail: `## Ciphertext byte order

Reverse each output word's four bytes back to Twofish's native little-endian
serialization — the mirror of the plaintext byte-order step at the start.`,
};

/** Aux namespace the key schedule publishes under (matches step defaults). */
const AUX_PREFIX = "twofish";
const auxK = (n: number): string => `${AUX_PREFIX}.K.${n}`;
const auxA = (i: number): string => `${AUX_PREFIX}.A.${i}`;
const auxB = (i: number): string => `${AUX_PREFIX}.B.${i}`;
const auxS = (b: number): string => `${AUX_PREFIX}.S${b}`;

/** Spell a port binding the way the runtime + editor expect it. */
const port = (node: string, portName: string): PortBinding => ({ node, port: portName });

/** Reverse each of the four 32-bit words of a 16-byte block (LE↔BE crossing). */
const WORD_REVERSE_16 = [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12];
/** Reverse one 4-byte word (the per-g LE↔BE crossing after the MDS multiply). */
const WORD_REVERSE_4 = [3, 2, 1, 0];

// Deep-copy the MDS matrix into fresh arrays so no two spec leaves share a
// param reference (the spec-builder discipline — see src/steps/CLAUDE.md).
const mdsParam = (): number[][] => TWOFISH_MDS.map((row) => [...row]);

// ─── Key setup: opaque monolith + visible PHT blocks ──────────────────────────

/**
 * Build the key-setup group. Default-collapsed so the ~180 setup chips don't
 * wall the canvas on first render (the decomposed-schedule posture).
 */
const buildKeySetup = (): StepNode => {
  const ks = (s: string) => `key-schedule.${s}`;
  const children: StepNode[] = [];

  // The 16-byte key → the opaque h-expand monolith.
  children.push({
    kind: "step",
    id: ks("load-key"),
    type: "aux-load-bytes@1",
    params: { auxName: "key", byteLength: 16 },
  });
  children.push({
    kind: "step",
    id: ks("h-expand"),
    type: "twofish.h-expand@1",
    params: { outputPrefix: AUX_PREFIX },
    portInputs: { key: port(ks("load-key"), "output") },
  });

  // 20 visible PHT blocks: K_{2i} = A_i + B_i; K_{2i+1} = ROL(A_i + 2·B_i, 9).
  const publishInputs: Record<string, PortBinding> = {};
  for (let i = 0; i < 20; i++) {
    const b = (s: string) => ks(`pht${i}.${s}`);
    // Load A_i, B_i from what h-expand published.
    children.push({
      kind: "step",
      id: b("loadA"),
      type: "aux-load-bytes@1",
      params: { auxName: auxA(i), byteLength: 4 },
      narrationOverride: narrLoadA(i),
    });
    children.push({
      kind: "step",
      id: b("loadB"),
      type: "aux-load-bytes@1",
      params: { auxName: auxB(i), byteLength: 4 },
      narrationOverride: narrLoadB(i),
    });
    // K_{2i} = A_i + B_i.
    children.push({
      kind: "step",
      id: b("k0"),
      type: "add-mod-32@1",
      params: { inputCount: 2 },
      portInputs: { operand0: port(b("loadA"), "output"), operand1: port(b("loadB"), "output") },
      narrationOverride: narrPhtK0(i),
    });
    // 2·B_i = B_i + B_i.
    children.push({
      kind: "step",
      id: b("dblB"),
      type: "add-mod-32@1",
      params: { inputCount: 2 },
      portInputs: { operand0: port(b("loadB"), "output"), operand1: port(b("loadB"), "output") },
      narrationOverride: narrPhtDblB(i),
    });
    // t = A_i + 2·B_i.
    children.push({
      kind: "step",
      id: b("t"),
      type: "add-mod-32@1",
      params: { inputCount: 2 },
      portInputs: { operand0: port(b("loadA"), "output"), operand1: port(b("dblB"), "output") },
      narrationOverride: narrPhtT(i),
    });
    // K_{2i+1} = ROL(t, 9) = ROR(t, 23).
    children.push({
      kind: "step",
      id: b("k1"),
      type: "rotate-bits-right@1",
      params: { bits: 23, wordBits: 32 },
      portInputs: { input: port(b("t"), "output") },
      narrationOverride: narrPhtK1(i),
    });
    publishInputs[`k${2 * i}`] = port(b("k0"), "output");
    publishInputs[`k${2 * i + 1}`] = port(b("k1"), "output");
  }

  // Gather the 40 subkeys and publish them to aux for the rounds/whitening.
  children.push({
    kind: "step",
    id: ks("publish"),
    type: "twofish.publish-subkeys@1",
    params: { outputPrefix: AUX_PREFIX },
    portInputs: publishInputs,
  });

  return {
    kind: "group",
    id: "key-schedule",
    label: "Key Setup",
    defaultCollapsed: true,
    children,
  };
};

// ─── The g function (shared by both g(R0) and g(ROL(R1,8))) ───────────────────

/**
 * Emit the g-function leaves for one 4-byte input word. `prefix` namespaces the
 * leaf ids; `inputBinding` is the BE word to substitute+mix. Returns the leaves
 * plus the binding of the final g output (BE-encoded g value). The four S-box
 * lookups read `split.out(3−k)` because the word is stored big-endian but the
 * spec's g indexes bytes little-endian (x0 = LSB).
 */
const buildG = (
  prefix: string,
  inputBinding: PortBinding,
): { nodes: StepNode[]; output: PortBinding } => {
  const g = (s: string) => `${prefix}.${s}`;
  const nodes: StepNode[] = [
    // Split the BE word into its 4 bytes: output0 = MSB (x3) … output3 = LSB (x0).
    {
      kind: "step",
      id: g("split"),
      type: "split-bytes@1",
      params: { widths: [1, 1, 1, 1] },
      portInputs: { input: inputBinding },
      narrationOverride: NARR_G_SPLIT,
    },
    // Four byte→byte S-box lookups (S_k reads x_k = split.out(3−k)).
    {
      kind: "step",
      id: g("s0"),
      type: "twofish.sbox-lookup@1",
      params: { sboxName: auxS(0) },
      portInputs: { index: port(g("split"), "output3") },
      narrationOverride: narrGSbox(0),
    },
    {
      kind: "step",
      id: g("s1"),
      type: "twofish.sbox-lookup@1",
      params: { sboxName: auxS(1) },
      portInputs: { index: port(g("split"), "output2") },
      narrationOverride: narrGSbox(1),
    },
    {
      kind: "step",
      id: g("s2"),
      type: "twofish.sbox-lookup@1",
      params: { sboxName: auxS(2) },
      portInputs: { index: port(g("split"), "output1") },
      narrationOverride: narrGSbox(2),
    },
    {
      kind: "step",
      id: g("s3"),
      type: "twofish.sbox-lookup@1",
      params: { sboxName: auxS(3) },
      portInputs: { index: port(g("split"), "output0") },
      narrationOverride: narrGSbox(3),
    },
    // Concatenate the four substituted bytes into the MDS input vector.
    {
      kind: "step",
      id: g("concat"),
      type: "concat@1",
      params: { inputCount: 4 },
      portInputs: {
        input0: port(g("s0"), "output"),
        input1: port(g("s1"), "output"),
        input2: port(g("s2"), "output"),
        input3: port(g("s3"), "output"),
      },
      narrationOverride: NARR_G_CONCAT,
    },
    // MDS multiply over GF(2⁸)/0x169.
    {
      kind: "step",
      id: g("mds"),
      type: "gf-matrix-multiply@2",
      params: { matrix: mdsParam(), fieldModulus: TWOFISH_MDS_POLY },
      portInputs: { input: port(g("concat"), "output") },
      narrationOverride: NARR_G_MDS,
    },
    // Reverse the 4 MDS output bytes → big-endian encoding of the g value.
    {
      kind: "step",
      id: g("perm"),
      type: "permute@1",
      params: { indices: [...WORD_REVERSE_4] },
      portInputs: { input: port(g("mds"), "output") },
      narrationOverride: NARR_G_PERM,
    },
  ];
  return { nodes, output: port(g("perm"), "output") };
};

// ─── One round (port-mode group) ──────────────────────────────────────────────

/**
 * Build round `roundIdx` (0-based). `k0Idx`/`k1Idx` are the two round-subkey
 * indices this round adds (encrypt: `2r+8`, `2r+9`). `seedInput` is supplied by
 * the caller (the input whitening for round 0, the previous round's `out`
 * otherwise). `decrypt` swaps the 1-bit rotations.
 */
const buildRound = (
  roundIdx: number,
  k0Idx: number,
  k1Idx: number,
  seedInput: PortBinding,
  decrypt: boolean,
): StepNode => {
  const p = `round.${roundIdx}`;
  const r = (node: string, portName: string) => port(`${p}.${node}`, portName);
  const children: StepNode[] = [];

  // Split the 16-byte round input into R0..R3.
  children.push({
    kind: "step",
    id: `${p}.split`,
    type: "split-bytes@1",
    params: { widths: [4, 4, 4, 4] },
    portInputs: { input: port(p, "in") },
    narrationOverride: NARR_ROUND_SPLIT,
  });

  // T0 = g(R0).
  const g0 = buildG(`${p}.g0`, r("split", "output0"));
  children.push(...g0.nodes);

  // T1 = g(ROL(R1, 8)).
  children.push({
    kind: "step",
    id: `${p}.rolR1`,
    type: "rotate-bits-right@1",
    params: { bits: 24, wordBits: 32 }, // ROL 8 = ROR 24
    portInputs: { input: r("split", "output1") },
    narrationOverride: NARR_ROL_R1,
  });
  const g1 = buildG(`${p}.g1`, r("rolR1", "output"));
  children.push(...g1.nodes);

  // Load this round's two subkeys.
  children.push({
    kind: "step",
    id: `${p}.loadK0`,
    type: "aux-load-bytes@1",
    params: { auxName: auxK(k0Idx), byteLength: 4 },
    narrationOverride: narrLoadK(k0Idx),
  });
  children.push({
    kind: "step",
    id: `${p}.loadK1`,
    type: "aux-load-bytes@1",
    params: { auxName: auxK(k1Idx), byteLength: 4 },
    narrationOverride: narrLoadK(k1Idx),
  });

  // F0 = T0 + T1 + K0 ; F1 = T0 + 2·T1 + K1.
  children.push({
    kind: "step",
    id: `${p}.f0`,
    type: "add-mod-32@1",
    params: { inputCount: 3 },
    portInputs: {
      operand0: g0.output,
      operand1: g1.output,
      operand2: r("loadK0", "output"),
    },
    narrationOverride: NARR_F0,
  });
  children.push({
    kind: "step",
    id: `${p}.dbl2T1`,
    type: "add-mod-32@1",
    params: { inputCount: 2 },
    portInputs: { operand0: g1.output, operand1: g1.output },
    narrationOverride: NARR_DBL_T1,
  });
  children.push({
    kind: "step",
    id: `${p}.f1`,
    type: "add-mod-32@1",
    params: { inputCount: 3 },
    portInputs: {
      operand0: g0.output,
      operand1: r("dbl2T1", "output"),
      operand2: r("loadK1", "output"),
    },
    narrationOverride: NARR_F1,
  });

  // The 1-bit-rotation Feistel mix. Encrypt: R2' = ROR(R2 ⊕ F0, 1),
  // R3' = ROL(R3, 1) ⊕ F1. Decrypt inverts the two rotations:
  // R2' = ROL(R2, 1) ⊕ F0, R3' = ROR(R3 ⊕ F1, 1).
  if (!decrypt) {
    // R2x = R2 ⊕ F0 ; R2' = ROR(R2x, 1).
    children.push({
      kind: "step",
      id: `${p}.r2x`,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: { operand0: r("split", "output2"), operand1: r("f0", "output") },
      narrationOverride: NARR_R2_XOR,
    });
    children.push({
      kind: "step",
      id: `${p}.r2p`,
      type: "rotate-bits-right@1",
      params: { bits: 1, wordBits: 32 }, // ROR 1
      portInputs: { input: r("r2x", "output") },
      narrationOverride: NARR_R2_ROT,
    });
    // R3r = ROL(R3, 1) ; R3' = R3r ⊕ F1.
    children.push({
      kind: "step",
      id: `${p}.r3r`,
      type: "rotate-bits-right@1",
      params: { bits: 31, wordBits: 32 }, // ROL 1 = ROR 31
      portInputs: { input: r("split", "output3") },
      narrationOverride: NARR_R3_ROT,
    });
    children.push({
      kind: "step",
      id: `${p}.r3p`,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: { operand0: r("r3r", "output"), operand1: r("f1", "output") },
      narrationOverride: NARR_R3_XOR,
    });
  } else {
    // Decrypt: R2' = ROL(R2, 1) ⊕ F0.
    children.push({
      kind: "step",
      id: `${p}.r2r`,
      type: "rotate-bits-right@1",
      params: { bits: 31, wordBits: 32 }, // ROL 1
      portInputs: { input: r("split", "output2") },
      narrationOverride: NARR_R3_ROT,
    });
    children.push({
      kind: "step",
      id: `${p}.r2p`,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: { operand0: r("r2r", "output"), operand1: r("f0", "output") },
      narrationOverride: NARR_R2_XOR,
    });
    // R3' = ROR(R3 ⊕ F1, 1).
    children.push({
      kind: "step",
      id: `${p}.r3x`,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: { operand0: r("split", "output3"), operand1: r("f1", "output") },
      narrationOverride: NARR_R3_XOR,
    });
    children.push({
      kind: "step",
      id: `${p}.r3p`,
      type: "rotate-bits-right@1",
      params: { bits: 1, wordBits: 32 }, // ROR 1
      portInputs: { input: r("r3x", "output") },
      narrationOverride: NARR_R2_ROT,
    });
  }

  // Recombine with the swap: next state = (R2', R3', R0, R1).
  children.push({
    kind: "step",
    id: `${p}.recombine`,
    type: "concat@1",
    params: { inputCount: 4 },
    portInputs: {
      input0: r("r2p", "output"),
      input1: r("r3p", "output"),
      input2: r("split", "output0"),
      input3: r("split", "output1"),
    },
    narrationOverride: NARR_RECOMBINE,
  });

  return {
    kind: "group",
    id: p,
    label: `Round ${roundIdx}`,
    seedInput,
    bodyOutput: r("recombine", "output"),
    children,
  };
};

// ─── Input whitening (top-level, feeds round 0) ───────────────────────────────

/**
 * Reverse each plaintext word (LE→BE), split into R0..R3, XOR with the four
 * whitening subkeys (`wIdx0..3`), recombine into the round-0 input. Returns the
 * nodes + the binding round 0 seeds from.
 */
const buildInputWhitening = (
  wIdx: readonly number[],
): { nodes: StepNode[]; output: PortBinding } => {
  const w = (s: string) => `whiten-in.${s}`;
  const nodes: StepNode[] = [
    {
      kind: "step",
      id: w("permute"),
      type: "permute@1",
      params: { indices: [...WORD_REVERSE_16] },
      portInputs: { input: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT) },
      narrationOverride: NARR_IN_PERMUTE,
    },
    {
      kind: "step",
      id: w("split"),
      type: "split-bytes@1",
      params: { widths: [4, 4, 4, 4] },
      portInputs: { input: port(w("permute"), "output") },
      narrationOverride: NARR_IN_SPLIT,
    },
  ];
  const concatInputs: Record<string, PortBinding> = {};
  for (let i = 0; i < 4; i++) {
    nodes.push({
      kind: "step",
      id: w(`r${i}`),
      type: "xor-with-aux@1",
      params: { auxName: auxK(wIdx[i] ?? i) },
      portInputs: { input: port(w("split"), `output${i}`) },
      narrationOverride: narrInWhiten(wIdx[i] ?? i),
    });
    concatInputs[`input${i}`] = port(w(`r${i}`), "output");
  }
  nodes.push({
    kind: "step",
    id: w("concat"),
    type: "concat@1",
    params: { inputCount: 4 },
    portInputs: concatInputs,
    narrationOverride: NARR_IN_CONCAT,
  });
  return { nodes, output: port(w("concat"), "output") };
};

// ─── Output whitening (top-level, after the last round) ───────────────────────

/**
 * Undo the final swap and XOR the four whitening subkeys (`wIdx0..3`) — the
 * swap-undo is the output-word ↔ round-output reindex `(i+2) mod 4`. Reverse
 * each word (BE→LE) → ciphertext. Returns the nodes + the cipher output binding.
 */
const buildOutputWhitening = (
  lastRoundId: string,
  wIdx: readonly number[],
): { nodes: StepNode[]; output: PortBinding } => {
  const w = (s: string) => `whiten-out.${s}`;
  // Output word i takes round-output word (i+2) mod 4 (undo the last swap).
  const src = [2, 3, 0, 1];
  const nodes: StepNode[] = [
    {
      kind: "step",
      id: w("split"),
      type: "split-bytes@1",
      params: { widths: [4, 4, 4, 4] },
      portInputs: { input: port(lastRoundId, "out") },
      narrationOverride: NARR_OUT_SPLIT,
    },
  ];
  const concatInputs: Record<string, PortBinding> = {};
  for (let i = 0; i < 4; i++) {
    nodes.push({
      kind: "step",
      id: w(`c${i}`),
      type: "xor-with-aux@1",
      params: { auxName: auxK(wIdx[i] ?? i) },
      portInputs: { input: port(w("split"), `output${src[i]}`) },
      narrationOverride: narrOutWhiten(wIdx[i] ?? i),
    });
    concatInputs[`input${i}`] = port(w(`c${i}`), "output");
  }
  nodes.push({
    kind: "step",
    id: w("concat"),
    type: "concat@1",
    params: { inputCount: 4 },
    portInputs: concatInputs,
    narrationOverride: NARR_OUT_CONCAT,
  });
  // Reverse each word → little-endian ciphertext.
  nodes.push({
    kind: "step",
    id: w("permute"),
    type: "permute@1",
    params: { indices: [...WORD_REVERSE_16] },
    portInputs: { input: port(w("concat"), "output") },
    narrationOverride: NARR_OUT_PERMUTE,
  });
  return { nodes, output: port(w("permute"), "output") };
};

// ─── Spec assembly ────────────────────────────────────────────────────────────

/** Build the Twofish encrypt or decrypt spec (128-bit key, v1). */
export const buildTwofishSpec = (direction: TwofishDirection): CipherSpec => {
  const encrypt = direction === "encrypt";

  // Whitening subkey indices. Encrypt: input K0..3, output K4..7. Decrypt swaps
  // them (input K4..7, output K0..3) — the standard Twofish decrypt symmetry.
  const inWhitening = encrypt ? [0, 1, 2, 3] : [4, 5, 6, 7];
  const outWhitening = encrypt ? [4, 5, 6, 7] : [0, 1, 2, 3];

  const { nodes: inWhiten, output: seed0 } = buildInputWhitening(inWhitening);

  const rounds: StepNode[] = [];
  let seed = seed0;
  for (let r = 0; r < TWOFISH_ROUNDS; r++) {
    // Encrypt consumes rounds/subkeys forward; decrypt reverses both. Round r's
    // two subkeys are K[8 + 2·rr] / K[9 + 2·rr] where rr is the ENCRYPT round
    // number this decrypt round undoes.
    const rr = encrypt ? r : TWOFISH_ROUNDS - 1 - r;
    const k0Idx = 8 + 2 * rr;
    const k1Idx = 9 + 2 * rr;
    rounds.push(buildRound(r, k0Idx, k1Idx, seed, !encrypt));
    seed = port(`round.${r}`, "out");
  }

  const { nodes: outWhiten, output } = buildOutputWhitening(
    `round.${TWOFISH_ROUNDS - 1}`,
    outWhitening,
  );

  return {
    id: encrypt ? "twofish@1" : "twofish-decrypt@1",
    name: "Twofish",
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: 16 },
    },
    steps: [buildKeySetup(), ...inWhiten, ...rounds, ...outWhiten],
    outputFrom: output,
  };
};
