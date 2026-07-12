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

import type { CipherSpec, PortBinding, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { TWOFISH_MDS, TWOFISH_MDS_POLY, TWOFISH_ROUNDS } from "./twofish-constants";

export type TwofishDirection = "encrypt" | "decrypt";

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
    });
    children.push({
      kind: "step",
      id: b("loadB"),
      type: "aux-load-bytes@1",
      params: { auxName: auxB(i), byteLength: 4 },
    });
    // K_{2i} = A_i + B_i.
    children.push({
      kind: "step",
      id: b("k0"),
      type: "add-mod-32@1",
      params: { inputCount: 2 },
      portInputs: { operand0: port(b("loadA"), "output"), operand1: port(b("loadB"), "output") },
    });
    // 2·B_i = B_i + B_i.
    children.push({
      kind: "step",
      id: b("dblB"),
      type: "add-mod-32@1",
      params: { inputCount: 2 },
      portInputs: { operand0: port(b("loadB"), "output"), operand1: port(b("loadB"), "output") },
    });
    // t = A_i + 2·B_i.
    children.push({
      kind: "step",
      id: b("t"),
      type: "add-mod-32@1",
      params: { inputCount: 2 },
      portInputs: { operand0: port(b("loadA"), "output"), operand1: port(b("dblB"), "output") },
    });
    // K_{2i+1} = ROL(t, 9) = ROR(t, 23).
    children.push({
      kind: "step",
      id: b("k1"),
      type: "rotate-bits-right@1",
      params: { bits: 23, wordBits: 32 },
      portInputs: { input: port(b("t"), "output") },
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
    },
    // Four byte→byte S-box lookups (S_k reads x_k = split.out(3−k)).
    {
      kind: "step",
      id: g("s0"),
      type: "twofish.sbox-lookup@1",
      params: { sboxName: auxS(0) },
      portInputs: { index: port(g("split"), "output3") },
    },
    {
      kind: "step",
      id: g("s1"),
      type: "twofish.sbox-lookup@1",
      params: { sboxName: auxS(1) },
      portInputs: { index: port(g("split"), "output2") },
    },
    {
      kind: "step",
      id: g("s2"),
      type: "twofish.sbox-lookup@1",
      params: { sboxName: auxS(2) },
      portInputs: { index: port(g("split"), "output1") },
    },
    {
      kind: "step",
      id: g("s3"),
      type: "twofish.sbox-lookup@1",
      params: { sboxName: auxS(3) },
      portInputs: { index: port(g("split"), "output0") },
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
    },
    // MDS multiply over GF(2⁸)/0x169.
    {
      kind: "step",
      id: g("mds"),
      type: "gf-matrix-multiply@2",
      params: { matrix: mdsParam(), fieldModulus: TWOFISH_MDS_POLY },
      portInputs: { input: port(g("concat"), "output") },
    },
    // Reverse the 4 MDS output bytes → big-endian encoding of the g value.
    {
      kind: "step",
      id: g("perm"),
      type: "permute@1",
      params: { indices: [...WORD_REVERSE_4] },
      portInputs: { input: port(g("mds"), "output") },
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
  });
  const g1 = buildG(`${p}.g1`, r("rolR1", "output"));
  children.push(...g1.nodes);

  // Load this round's two subkeys.
  children.push({
    kind: "step",
    id: `${p}.loadK0`,
    type: "aux-load-bytes@1",
    params: { auxName: auxK(k0Idx), byteLength: 4 },
  });
  children.push({
    kind: "step",
    id: `${p}.loadK1`,
    type: "aux-load-bytes@1",
    params: { auxName: auxK(k1Idx), byteLength: 4 },
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
  });
  children.push({
    kind: "step",
    id: `${p}.dbl2T1`,
    type: "add-mod-32@1",
    params: { inputCount: 2 },
    portInputs: { operand0: g1.output, operand1: g1.output },
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
    });
    children.push({
      kind: "step",
      id: `${p}.r2p`,
      type: "rotate-bits-right@1",
      params: { bits: 1, wordBits: 32 }, // ROR 1
      portInputs: { input: r("r2x", "output") },
    });
    // R3r = ROL(R3, 1) ; R3' = R3r ⊕ F1.
    children.push({
      kind: "step",
      id: `${p}.r3r`,
      type: "rotate-bits-right@1",
      params: { bits: 31, wordBits: 32 }, // ROL 1 = ROR 31
      portInputs: { input: r("split", "output3") },
    });
    children.push({
      kind: "step",
      id: `${p}.r3p`,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: { operand0: r("r3r", "output"), operand1: r("f1", "output") },
    });
  } else {
    // Decrypt: R2' = ROL(R2, 1) ⊕ F0.
    children.push({
      kind: "step",
      id: `${p}.r2r`,
      type: "rotate-bits-right@1",
      params: { bits: 31, wordBits: 32 }, // ROL 1
      portInputs: { input: r("split", "output2") },
    });
    children.push({
      kind: "step",
      id: `${p}.r2p`,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: { operand0: r("r2r", "output"), operand1: r("f0", "output") },
    });
    // R3' = ROR(R3 ⊕ F1, 1).
    children.push({
      kind: "step",
      id: `${p}.r3x`,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: { operand0: r("split", "output3"), operand1: r("f1", "output") },
    });
    children.push({
      kind: "step",
      id: `${p}.r3p`,
      type: "rotate-bits-right@1",
      params: { bits: 1, wordBits: 32 }, // ROR 1
      portInputs: { input: r("r3x", "output") },
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
    },
    {
      kind: "step",
      id: w("split"),
      type: "split-bytes@1",
      params: { widths: [4, 4, 4, 4] },
      portInputs: { input: port(w("permute"), "output") },
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
    });
    concatInputs[`input${i}`] = port(w(`r${i}`), "output");
  }
  nodes.push({
    kind: "step",
    id: w("concat"),
    type: "concat@1",
    params: { inputCount: 4 },
    portInputs: concatInputs,
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
    });
    concatInputs[`input${i}`] = port(w(`c${i}`), "output");
  }
  nodes.push({
    kind: "step",
    id: w("concat"),
    type: "concat@1",
    params: { inputCount: 4 },
    portInputs: concatInputs,
  });
  // Reverse each word → little-endian ciphertext.
  nodes.push({
    kind: "step",
    id: w("permute"),
    type: "permute@1",
    params: { indices: [...WORD_REVERSE_16] },
    portInputs: { input: port(w("concat"), "output") },
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
