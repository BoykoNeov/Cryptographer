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

import type { CipherSpec, PortBinding, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { BLOWFISH_P_INIT, BLOWFISH_ROUNDS, u32ToBytesBE } from "./blowfish-constants";

export type BlowfishDirection = "encrypt" | "decrypt";

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
const buildKeySetup = (): StepNode => {
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
      },
      // L1 = L ⊕ P[pIdx]  (reuses the parameterizable generic xor-with-aux).
      {
        kind: "step",
        id: `${p}.xorP`,
        type: "xor-with-aux@1",
        params: { auxName: auxP(pIdx) },
        portInputs: { input: r("split", "output0") },
      },
      // F(L1): split into 4 bytes, look each up in S0..S3, then combine.
      {
        kind: "step",
        id: `${p}.splitF`,
        type: "split-bytes@1",
        params: { widths: [1, 1, 1, 1] },
        portInputs: { input: r("xorP", "output") },
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
      },
      // t2 = t1 ⊕ S2[c]
      {
        kind: "step",
        id: `${p}.xor2`,
        type: "xor@1",
        params: { inputCount: 2 },
        portInputs: { operand0: r("add01", "output"), operand1: r("s2", "output") },
      },
      // Fout = t2 + S3[d]   (mod 2^32)
      {
        kind: "step",
        id: `${p}.add3`,
        type: "add-mod-32@1",
        params: { inputCount: 2 },
        portInputs: { operand0: r("xor2", "output"), operand1: r("s3", "output") },
      },
      // R1 = F(L1) ⊕ R
      {
        kind: "step",
        id: `${p}.xorR`,
        type: "xor@1",
        params: { inputCount: 2 },
        portInputs: { operand0: r("add3", "output"), operand1: r("split", "output1") },
      },
      // Recombine as R1 || L1 — the Feistel swap IS the concat argument order.
      {
        kind: "step",
        id: `${p}.recombine`,
        type: "concat@1",
        params: { inputCount: 2 },
        portInputs: { input0: r("xorR", "output"), input1: r("xorP", "output") },
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
    },
    // right = A ⊕ P[rightP]
    {
      kind: "step",
      id: w("right"),
      type: "xor-with-aux@1",
      params: { auxName: auxP(rightP) },
      portInputs: { input: port(w("split"), "output0") },
    },
    // Output block = left || right.
    {
      kind: "step",
      id: w("concat"),
      type: "concat@1",
      params: { inputCount: 2 },
      portInputs: { input0: port(w("left"), "output"), input1: port(w("right"), "output") },
    },
  ];
  return { nodes, output: port(w("concat"), "output") };
};

// ─── Spec assembly ────────────────────────────────────────────────────────────

/** Build the Blowfish encrypt or decrypt spec. */
export const buildBlowfishSpec = (direction: BlowfishDirection): CipherSpec => {
  const encrypt = direction === "encrypt";
  const rounds: StepNode[] = [];
  for (let j = 1; j <= BLOWFISH_ROUNDS; j++) {
    const pIdx = encrypt ? j - 1 : 18 - j;
    const seed = j === 1 ? port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT) : port(`round.${j - 1}`, "out");
    rounds.push(buildRound(j, pIdx, seed));
  }
  const { nodes: whitening, output } = encrypt ? buildWhitening(17, 16) : buildWhitening(0, 1);

  return {
    id: encrypt ? "blowfish@1" : "blowfish-decrypt@1",
    name: "Blowfish",
    stateShape: "bytes",
    inputs: {
      plaintext: { shape: "bytes" },
      key: { byteLength: 8 },
    },
    steps: [buildKeySetup(), ...rounds, ...whitening],
    outputFrom: output,
  };
};
