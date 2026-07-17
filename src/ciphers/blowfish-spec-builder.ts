/**
 * Blowfish spec builder (Schneier 1993) — the fifth cipher family and the
 * second Feistel cipher after DES.
 *
 * `buildBlowfishSpec(direction)` constructs the encrypt or decrypt spec; the
 * two differ ONLY in which P-array slot each round + the whitening consume
 * (Blowfish decrypts by running the same network with the P-array applied in
 * reverse — no inverse S-boxes, no separate decrypt code path). One builder,
 * two specs, mirroring the Speck / DES precedent.
 *
 * ## Structure
 *
 * 1. **Key setup** (default-collapsed group). Per the user's "visible key-mix
 *    + opaque loop" choice: the `key ⊕ P` mixing is shown as 18 real `xor@1`
 *    frames (how a variable-length key enters the cipher), whose `concat@1`
 *    feeds the ONE opaque `blowfish.key-schedule@1` monolith. The monolith runs
 *    the 521 self-encryptions and publishes the final P-array + four S-boxes
 *    into `aux["blowfish.P.0..17"]` + `aux["blowfish.S0..S3"]`.
 *
 * 2. **16 Feistel rounds** (port-mode groups, DES-style — the swap IS the
 *    `concat@1` argument order). Each round:
 *      - `split-bytes [4,4]` → L, R
 *      - `xor-with-aux(L, P[idx])`         → L1     (reuses the generic step's
 *                                                    parameterizable auxName)
 *      - **F(L1):** `split-bytes [1,1,1,1]` → a,b,c,d; four
 *        `blowfish.sbox-lookup` → S0[a],S1[b],S2[c],S3[d];
 *        `add-mod-32(S0,S1)` → `xor(.,S2)` → `add-mod-32(.,S3)` = Fout
 *      - `xor(Fout, R)`                    → R1
 *      - `concat(R1, L1)` — the Feistel swap
 *
 * 3. **Final whitening** (undo the last loop swap + XOR the two remaining P
 *    words): `split-bytes [4,4]` the round-16 output into A,B; XOR B and A with
 *    the whitening P words; `concat` → the output block. Traced against the
 *    reference in `docs/plans/blowfish.md`:
 *      - encrypt: `ct = (B ⊕ P[17]) || (A ⊕ P[16])`
 *      - decrypt: `pt = (B ⊕ P[0])  || (A ⊕ P[1])`
 *
 * ## Direction parameterization
 *
 *   - Round `j` (1-based) consumes P index `j-1` on encrypt, `18-j` on decrypt.
 *   - Whitening consumes (left, right) = (P17, P16) on encrypt, (P0, P1) on
 *     decrypt.
 *
 * The key-setup group is IDENTICAL for both directions (both derive the full
 * P/S); only the consumption indices differ.
 */

import type { CipherSpec, PortBinding, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { BLOWFISH_P_INIT, BLOWFISH_ROUNDS, u32ToBytesBE } from "./blowfish-constants";

export type BlowfishDirection = "encrypt" | "decrypt";

// ─── narrationOverride docs (Blowfish-friendly names for the generic leaves) ──
// The round body reuses GENERIC primitives (`split-bytes` / `xor-with-aux` /
// `add-mod-32` / `xor` / `concat`) that otherwise render as "Split Bytes / XOR
// with Aux / Add mod 2^32" in the inspector — opaque for a learner. These
// overrides name the Blowfish role each leaf plays, mirroring RSA's per-rung
// ladder narration (RSA's `mul`/`mod-mul` reuse is the same situation). Shared
// static docs per role (the DES key-schedule `NARR_*` idiom); the few that need
// a subkey index take function form. The `blowfish.sbox-lookup@1` /
// `blowfish.key-schedule@1` leaves already carry rich cipher-specific registry
// docs, so they need no override.

const NARR_SPLIT: StepDocumentation = {
  name: "Split into L | R",
  summary: "Split the 8-byte block into the two 32-bit Feistel halves L and R.",
  detail: `## Split into L ‖ R

The 64-bit block divides into the left half **L** (bytes 0–3) and the right
half **R** (bytes 4–7). Only L is transformed this round; the halves swap at the
end (which is just the recombine's argument order).`,
};

const narrXorP = (pIdx: number): StepDocumentation => ({
  name: `L ⊕ P[${pIdx}]`,
  summary: `XOR this round's subkey word P[${pIdx}] into the left half.`,
  detail: `## L ⊕ P[${pIdx}]

Each round begins by XORing its P-array subkey word **P[${pIdx}]** into the left
half. This is where key material enters the round directly; the four S-box
lookups in F carry the rest of the key's influence (the S-boxes were themselves
derived from the key). Decryption uses the same P-array in reverse order.`,
});

const NARR_SPLIT_F: StepDocumentation = {
  name: "Split into a,b,c,d",
  summary: "Split the 32-bit F-function input into its four bytes.",
  detail: `## F-function input split

F looks each byte of its 32-bit input up in a different S-box, so the word
splits into four bytes **a b c d** (most-significant first) indexing S0, S1, S2,
S3 respectively.`,
};

const NARR_ADD01: StepDocumentation = {
  name: "S0[a] + S1[b]",
  summary: "Add the first two S-box outputs, mod 2³².",
  detail: `## F: S0[a] + S1[b]

The first combine in Blowfish's F function adds the S0 and S1 lookups modulo
2³². F deliberately mixes group operations — two adds over ℤ/2³² and one XOR over
GF(2)³² — and that mismatch is the source of its non-linearity.`,
};

const NARR_XOR2: StepDocumentation = {
  name: "⊕ S2[c]",
  summary: "XOR the S2 lookup into the running F value.",
  detail: `## F: ⊕ S2[c]

XOR the third S-box output S2[c] into \`S0[a] + S1[b]\` — the single XOR in F,
sandwiched between the two modular adds.`,
};

const NARR_ADD3: StepDocumentation = {
  name: "+ S3[d] = F",
  summary: "Add the S3 lookup (mod 2³²) to complete F(L').",
  detail: `## F: + S3[d]

Add the fourth S-box output to finish
\`F = ((S0[a] + S1[b]) ⊕ S2[c]) + S3[d]\`.`,
};

const NARR_XOR_R: StepDocumentation = {
  name: "R ⊕ F",
  summary: "XOR the F-function output into the right half — the Feistel mix.",
  detail: `## R ⊕ F

The Feistel mix: the right half is XORed with F of the subkey-mixed left half.
Together with the swap below, this is the entire round.`,
};

const NARR_RECOMBINE: StepDocumentation = {
  name: "Swap → (R⊕F) ‖ (L⊕P)",
  summary: "Recombine with the halves swapped — the Feistel exchange.",
  detail: `## Swap and recombine

The round output is \`(R ⊕ F) ‖ (L ⊕ P)\`: the new left half is the old (mixed)
right half, and vice-versa. **The swap is nothing more than this concatenation
order** — Blowfish, like every Feistel cipher here, needs no dedicated swap
step.`,
};

const narrMix = (i: number): StepDocumentation => ({
  name: `P[${i}] ⊕ key word ${i % 2}`,
  summary: `Mix key word ${i % 2} into π P-array seed word ${i}.`,
  detail: `## Key mixing: P[${i}]

The key enters Blowfish by XORing its words (cycling with wraparound) into the
π-derived P-array seed. With an 8-byte key there are two key words that
alternate across the 18 slots, so P[${i}] takes key word ${i % 2}. **These 18
XORs are the *visible* part of the key schedule**; the 521-encryption loop that
consumes their result is the one opaque step.`,
});

const narrWhitenXor = (pIdx: number): StepDocumentation => ({
  name: `⊕ P[${pIdx}]`,
  summary: `Final whitening: XOR the remaining subkey word P[${pIdx}].`,
  detail: `## Output whitening: ⊕ P[${pIdx}]

After the 16 rounds, Blowfish undoes the final swap and XORs the two P-array
words the round loop never used (P[16], P[17] on encrypt; P[0], P[1] on decrypt)
into the two halves. This half applies **P[${pIdx}]**.`,
});

const NARR_WHITEN_CONCAT: StepDocumentation = {
  name: "Output block",
  summary: "Concatenate the two whitened halves into the 8-byte output.",
  detail: `## Output block

The two whitened halves join into the final 8-byte block — the ciphertext (or,
in decrypt mode, the recovered plaintext).`,
};

/** Aux namespace the key schedule publishes under (must match the monolith's
 *  default `outputPrefix`). */
const AUX_PREFIX = "blowfish";
const auxP = (i: number): string => `${AUX_PREFIX}.P.${i}`;
const auxS = (b: number): string => `${AUX_PREFIX}.S${b}`;

/** Spell a port binding the way the runtime + editor expect it. */
const port = (node: string, portName: string): PortBinding => ({ node, port: portName });

// ─── Key setup: visible key-mix + the opaque monolith ─────────────────────────

/**
 * Serialize the 18 π P-array seed words into 72 big-endian bytes for the
 * `constant-load@1` that seeds the visible key-mix. (This is the ONLY π table
 * that enters the spec; the 4 KB of S-boxes stay module-const inside the
 * monolith — see `blowfish-constants.ts`.)
 */
const piPInitBytes = (): number[] => {
  const out: number[] = [];
  for (let i = 0; i < BLOWFISH_P_INIT.length; i++) {
    const b = u32ToBytesBE(BLOWFISH_P_INIT[i] ?? 0);
    out.push(b[0] ?? 0, b[1] ?? 0, b[2] ?? 0, b[3] ?? 0);
  }
  return out;
};

/**
 * The key-setup group. `key ⊕ P` mixing as 18 visible `xor@1` frames, then the
 * opaque `blowfish.key-schedule@1` monolith. Default-collapsed so the ~25
 * setup chips don't wall the canvas on first render (AES/Speck/Serpent/DES
 * decomposed-schedule posture).
 *
 * The key is fixed at 8 bytes for v1, so there are exactly two distinct key
 * words (`kw0` = key[0..3], `kw1` = key[4..7]) that alternate across the 18
 * P slots (the general cycling-with-wraparound rule collapses to alternation).
 */
export const buildKeySetup = (): StepNode => {
  const ks = (s: string) => `key-schedule.${s}`;
  const children: StepNode[] = [];

  // π P-array seed (72 bytes) → split into 18 words.
  children.push({
    kind: "step",
    id: ks("load-piP"),
    type: "constant-load@1",
    params: { bytes: piPInitBytes() },
  });
  children.push({
    kind: "step",
    id: ks("split-piP"),
    type: "split-bytes@1",
    params: { widths: Array.from({ length: 18 }, () => 4) },
    portInputs: { input: port(ks("load-piP"), "output") },
  });

  // The 8-byte key → two 4-byte key words (kw0, kw1).
  children.push({
    kind: "step",
    id: ks("load-key"),
    type: "aux-load-bytes@1",
    params: { auxName: "key", byteLength: 8 },
  });
  children.push({
    kind: "step",
    id: ks("kw0"),
    type: "byte-slice@1",
    params: { sourceByteLength: 8, offset: 0, length: 4 },
    portInputs: { input: port(ks("load-key"), "output") },
  });
  children.push({
    kind: "step",
    id: ks("kw1"),
    type: "byte-slice@1",
    params: { sourceByteLength: 8, offset: 4, length: 4 },
    portInputs: { input: port(ks("load-key"), "output") },
  });

  // 18 visible XORs: P[i] ⊕ kw(i mod 2). ← the key-mix.
  const concatInputs: Record<string, PortBinding> = {};
  for (let i = 0; i < 18; i++) {
    const kwId = i % 2 === 0 ? ks("kw0") : ks("kw1");
    children.push({
      kind: "step",
      id: ks(`mix${i}`),
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: port(ks("split-piP"), `output${i}`),
        operand1: port(kwId, "output"),
      },
      narrationOverride: narrMix(i),
    });
    concatInputs[`input${i}`] = port(ks(`mix${i}`), "output");
  }

  // Concat the 18 key-mixed words → 72-byte key-mixed P.
  children.push({
    kind: "step",
    id: ks("mixedP"),
    type: "concat@1",
    params: { inputCount: 18 },
    portInputs: concatInputs,
  });

  // The opaque 521-loop monolith → publishes aux[blowfish.P.*, blowfish.S*].
  children.push({
    kind: "step",
    id: ks("loop"),
    type: "blowfish.key-schedule@1",
    params: { outputPrefix: AUX_PREFIX },
    portInputs: { keyMixedP: port(ks("mixedP"), "output") },
  });

  return {
    kind: "group",
    id: "key-schedule",
    label: "Key Setup",
    defaultCollapsed: true,
    children,
  };
};

// ─── One Feistel round (port-mode group) ──────────────────────────────────────

/**
 * Build round `roundIdx` (1-based) as a port-mode group. `pIdx` is the P-array
 * slot this round XORs into L (encrypt: `roundIdx-1`; decrypt: `18-roundIdx`).
 * `seedInput` is supplied by the caller — round 1 seeds from the reserved
 * `$input` source, later rounds from the previous round's published `out`.
 */
const buildRound = (roundIdx: number, pIdx: number, seedInput: PortBinding): StepNode => {
  const p = `round.${roundIdx}`;
  const r = (node: string, portName: string) => port(`${p}.${node}`, portName);
  return {
    kind: "group",
    id: p,
    label: `Round ${roundIdx}`,
    seedInput,
    bodyOutput: r("recombine", "output"),
    children: [
      // Split the 8-byte round input into L (bytes 0..3) and R (bytes 4..7).
      {
        kind: "step",
        id: `${p}.split`,
        type: "split-bytes@1",
        params: { widths: [4, 4] },
        portInputs: { input: port(p, "in") },
        narrationOverride: NARR_SPLIT,
      },
      // L1 = L ⊕ P[pIdx]  (reuses the parameterizable generic xor-with-aux).
      {
        kind: "step",
        id: `${p}.xorP`,
        type: "xor-with-aux@1",
        params: { auxName: auxP(pIdx) },
        portInputs: { input: r("split", "output0") },
        narrationOverride: narrXorP(pIdx),
      },
      // F(L1): split into 4 bytes, look each up in S0..S3, then combine.
      {
        kind: "step",
        id: `${p}.splitF`,
        type: "split-bytes@1",
        params: { widths: [1, 1, 1, 1] },
        portInputs: { input: r("xorP", "output") },
        narrationOverride: NARR_SPLIT_F,
      },
      {
        kind: "step",
        id: `${p}.s0`,
        type: "blowfish.sbox-lookup@1",
        params: { sboxName: auxS(0) },
        portInputs: { index: r("splitF", "output0") },
      },
      {
        kind: "step",
        id: `${p}.s1`,
        type: "blowfish.sbox-lookup@1",
        params: { sboxName: auxS(1) },
        portInputs: { index: r("splitF", "output1") },
      },
      {
        kind: "step",
        id: `${p}.s2`,
        type: "blowfish.sbox-lookup@1",
        params: { sboxName: auxS(2) },
        portInputs: { index: r("splitF", "output2") },
      },
      {
        kind: "step",
        id: `${p}.s3`,
        type: "blowfish.sbox-lookup@1",
        params: { sboxName: auxS(3) },
        portInputs: { index: r("splitF", "output3") },
      },
      // t1 = S0[a] + S1[b]   (mod 2^32)
      {
        kind: "step",
        id: `${p}.add01`,
        type: "add-mod-32@1",
        params: { inputCount: 2 },
        portInputs: { operand0: r("s0", "output"), operand1: r("s1", "output") },
        narrationOverride: NARR_ADD01,
      },
      // t2 = t1 ⊕ S2[c]
      {
        kind: "step",
        id: `${p}.xor2`,
        type: "xor@1",
        params: { inputCount: 2 },
        portInputs: { operand0: r("add01", "output"), operand1: r("s2", "output") },
        narrationOverride: NARR_XOR2,
      },
      // Fout = t2 + S3[d]   (mod 2^32)
      {
        kind: "step",
        id: `${p}.add3`,
        type: "add-mod-32@1",
        params: { inputCount: 2 },
        portInputs: { operand0: r("xor2", "output"), operand1: r("s3", "output") },
        narrationOverride: NARR_ADD3,
      },
      // R1 = F(L1) ⊕ R
      {
        kind: "step",
        id: `${p}.xorR`,
        type: "xor@1",
        params: { inputCount: 2 },
        portInputs: { operand0: r("add3", "output"), operand1: r("split", "output1") },
        narrationOverride: NARR_XOR_R,
      },
      // Recombine as R1 || L1 — the Feistel swap IS the concat argument order.
      {
        kind: "step",
        id: `${p}.recombine`,
        type: "concat@1",
        params: { inputCount: 2 },
        portInputs: { input0: r("xorR", "output"), input1: r("xorP", "output") },
        narrationOverride: NARR_RECOMBINE,
      },
    ],
  };
};

// ─── Whitening (undo final swap + XOR the last two P words) ────────────────────

/**
 * Build the final whitening leaves. `leftP`/`rightP` are the P slots XORed into
 * the two halves of the round-16 output `A || B`:
 *   output = (B ⊕ P[leftP]) || (A ⊕ P[rightP])
 * Encrypt: (leftP, rightP) = (17, 16); decrypt: (0, 1). Returns the nodes plus
 * the final concat's output binding (the cipher's `outputFrom`).
 */
const buildWhitening = (
  leftP: number,
  rightP: number,
): { nodes: StepNode[]; output: PortBinding } => {
  const w = (s: string) => `whiten.${s}`;
  const nodes: StepNode[] = [
    // Split the round-16 output into A (bytes 0..3) and B (bytes 4..7).
    {
      kind: "step",
      id: w("split"),
      type: "split-bytes@1",
      params: { widths: [4, 4] },
      portInputs: { input: port(`round.${BLOWFISH_ROUNDS}`, "out") },
    },
    // left = B ⊕ P[leftP]
    {
      kind: "step",
      id: w("left"),
      type: "xor-with-aux@1",
      params: { auxName: auxP(leftP) },
      portInputs: { input: port(w("split"), "output1") },
      narrationOverride: narrWhitenXor(leftP),
    },
    // right = A ⊕ P[rightP]
    {
      kind: "step",
      id: w("right"),
      type: "xor-with-aux@1",
      params: { auxName: auxP(rightP) },
      portInputs: { input: port(w("split"), "output0") },
      narrationOverride: narrWhitenXor(rightP),
    },
    // Output block = left || right.
    {
      kind: "step",
      id: w("concat"),
      type: "concat@1",
      params: { inputCount: 2 },
      portInputs: { input0: port(w("left"), "output"), input1: port(w("right"), "output") },
      narrationOverride: NARR_WHITEN_CONCAT,
    },
  ];
  return { nodes, output: port(w("concat"), "output") };
};

// ─── Spec assembly ────────────────────────────────────────────────────────────

/**
 * The cipher body — 16 Feistel rounds + the final whitening — reading its block
 * from `seed`. Excludes the key setup, which a mode of operation runs ONCE
 * outside the per-block loop (the schedule publishes to aux, and aux is global,
 * so it crosses the iterate's scope boundary freely).
 *
 * The seed is a parameter rather than a hardcoded `$input` because a body inside
 * a port-mode `iterate` receives its block on the iterate's injected port, and
 * the runtime seeds `$input` at top scope only — a body that hardcodes it throws
 * inside the loop. The single-block spec below passes `$input`; `blowfish-core.ts`
 * passes whatever the mode hands it. This is the whole of the seed-threading
 * work a cipher needs to gain every mode (`docs/plans/foamy-prancing-wren.md`).
 */
export const buildBlowfishBody = (
  direction: BlowfishDirection,
  seed: PortBinding,
): { nodes: StepNode[]; output: PortBinding } => {
  const encrypt = direction === "encrypt";
  const rounds: StepNode[] = [];
  for (let j = 1; j <= BLOWFISH_ROUNDS; j++) {
    const pIdx = encrypt ? j - 1 : 18 - j;
    // Round 1 takes the caller's seed; later rounds chain off their predecessor.
    const roundSeed = j === 1 ? seed : port(`round.${j - 1}`, "out");
    rounds.push(buildRound(j, pIdx, roundSeed));
  }
  const { nodes: whitening, output } = encrypt ? buildWhitening(17, 16) : buildWhitening(0, 1);
  return { nodes: [...rounds, ...whitening], output };
};

/** Build the single-block Blowfish encrypt or decrypt spec. */
export const buildBlowfishSpec = (direction: BlowfishDirection): CipherSpec => {
  const { nodes, output } = buildBlowfishBody(direction, port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT));

  return {
    id: direction === "encrypt" ? "blowfish@1" : "blowfish-decrypt@1",
    name: "Blowfish",
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: 8 },
    },
    steps: [buildKeySetup(), ...nodes],
    outputFrom: output,
  };
};
