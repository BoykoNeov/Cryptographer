/**
 * Byte-native Serpent key-schedule construction — key-schedule-decomposition
 * plan slice K3a (2026-06-02). The port-native replacement for the monolithic
 * `serpent.key-expansion@1` executor.
 *
 * **Why decompose.** The monolith ran the whole Anderson/Biham/Knudsen 1998 §2
 * schedule (pad → 8 LE prekey words → the 132-word recurrence → bitsliced
 * S-box per group → IP per round key) inside ONE executor — invisible to the
 * trace. This builder expresses the same math as a tree of port-native
 * primitives so every sub-step is a scrubbable frame, the same way
 * `aes-key-schedule-builder-native.ts` (K1a) and
 * `speck-32-64-key-schedule-builder-native.ts` (K2a) already do for AES/Speck.
 *
 * **B-minimal (producer-only).** The recurrence is visible; a single
 * meta-bearing `serpent.publish-round-keys@1` tail writes `aux["roundKey.0..32"]`
 * byte-identically to the monolith, so the round-body consumers
 * (`serpent.add-round-key@1` reading `aux[roundKeyAux]` via `meta.auxReadPorts`)
 * and the six shipped Serpent specs' round arrangement stay UNTOUCHED.
 *
 * **Byte-order codec at the input boundary (K3 advisor pick 2026-06-02).**
 * Serpent prekeys are LITTLE-ENDIAN 32-bit words (`readWordLE32`), but the
 * `rotate-bits-right@1` primitive reads/writes BIG-ENDIAN words. So the
 * recurrence runs in BE: ONE `permute@1` input codec byte-swaps every 4-byte
 * word LE→BE right after the master-split (and after the optional pad), and the
 * whole recurrence + the `serpent.key-sbox@1` leaves then operate uniformly on
 * BE 32-bit words. XOR / constant-load are byte-wise (byte-order-invariant), so
 * only the rotate needs the BE view. There is NO output codec — `serpent.key-
 * sbox@1` lifts the oracle's S-box+IP verbatim (LE serialize + IP), emitting the
 * monolith's exact round-key bytes, and Serpent has a single publish convention.
 *
 * **The recurrence (ABK 1998 §2), loop counter j = 0 … 131 (array idx = j+8):**
 *   w_{idx} = ROL(w_{idx-8} ⊕ w_{idx-5} ⊕ w_{idx-3} ⊕ w_{idx-1} ⊕ phi ⊕ j, 11)
 * with phi = 0x9e3779b9. Each tap prekey index p < 8 is a seed word
 * (master-split.output{p}); p ≥ 8 is iteration (p-8)'s `new` output. ROL11 is
 * implemented as ROR(32 - 11) = ROR21 via `rotate-bits-right@1`.
 *
 * **The 33 round keys.** Group i takes prekey words 8+4i .. 8+4i+3 (i.e.
 * iterations 4i .. 4i+3), concatenates them, and feeds `serpent.key-sbox@1`
 * with `sboxIndex = (((35 - i) % 8) + 8) % 8`. The S-box+IP leaf produces the
 * 16-byte round key directly. Fixed 33 round keys for all three key sizes.
 *
 * **Pad-to-256.** For 16/24-byte keys, pad to 32 bytes by appending `0x01`
 * then zeros (LSB-first padding: a single 1-bit immediately after the last key
 * bit). Expressed as `concat@1` of the loaded key + a `constant-load@1` of the
 * padding tail. 32-byte keys skip the pad entirely.
 */

import type { PortBinding, StepDocumentation, StepNode } from "../core/types";
import { SERPENT_PHI } from "./serpent-constants";

// ─── PortBinding + name helpers ───────────────────────────────────────────────

const port = (node: string, portName: string): PortBinding => ({ node, port: portName });
const ks = (suffix: string): string => `key-schedule.${suffix}`;

/** phi = 0x9e3779b9 as 4 BIG-ENDIAN bytes (the byte-wise XOR is order-
 *  invariant, but the recurrence reads everything BE, so phi is BE too). */
const PHI_BE_BYTES: readonly number[] = [
  (SERPENT_PHI >>> 24) & 0xff,
  (SERPENT_PHI >>> 16) & 0xff,
  (SERPENT_PHI >>> 8) & 0xff,
  SERPENT_PHI & 0xff,
];

/** A 32-bit loop counter j as 4 BIG-ENDIAN bytes. */
const j32BE = (j: number): number[] => [
  (j >>> 24) & 0xff,
  (j >>> 16) & 0xff,
  (j >>> 8) & 0xff,
  j & 0xff,
];

/** Per-4-byte-word byte-swap (LE↔BE) permute indices over an `nWords`-word
 *  buffer: each word [a,b,c,d] → [d,c,b,a]. */
const wordByteSwapIndices = (nWords: number): number[] => {
  const indices: number[] = [];
  for (let w = 0; w < nWords; w++) {
    const base = w * 4;
    indices.push(base + 3, base + 2, base + 1, base);
  }
  return indices;
};

// ─── narrationOverride docs (ABK 1998 §2 friendly names) ──────────────────────
// One shared static doc per role (the op is identical every iteration; the
// per-iteration specifics are the frame's byte values). Mirrors the AES / Speck
// key-schedule narration idiom.

const NARR_LOAD_KEY: StepDocumentation = {
  name: "Load master key",
  summary: "Load the 16/24/32-byte master key from aux to seed the schedule.",
  detail: `## Load master key

The Serpent master key (16 / 24 / 32 bytes for Serpent-128 / 192 / 256) is read
from \`aux["key"]\`. Shorter keys are padded to 256 bits below before being
viewed as eight little-endian prekey words.`,
  references: ["Anderson, Biham, Knudsen 1998, §2 (Key Schedule)"],
};

const NARR_PAD: StepDocumentation = {
  name: "Pad to 256 bits",
  summary: "Append a single 1-bit (0x01) then zeros to fill the key out to 32 bytes.",
  detail: `## Pad to 256 bits

Serpent expands a 256-bit padded key. If the master key is shorter, append a
single \`1\` bit immediately after the last key bit, then zeros to 256 bits.
With LSB-first bit numbering inside each byte, that is just \`padded[keyLen] =
0x01\` and the rest zero. A 256-bit key skips this step.`,
  references: ["Anderson, Biham, Knudsen 1998, §2 (step 1)"],
};

const NARR_PAD_CONST: StepDocumentation = {
  name: "Padding tail (0x01, 0…)",
  summary: "The constant padding bytes appended after the master key.",
  detail: `## Padding tail

The bytes appended after the master key to reach 32 bytes: a single \`0x01\`
(the padding "1" bit, LSB-first) followed by zeros.`,
  references: ["Anderson, Biham, Knudsen 1998, §2 (step 1)"],
};

const NARR_INPUT_CODEC: StepDocumentation = {
  name: "Decode prekeys (LE→BE)",
  summary: "Byte-swap each 32-bit word: Serpent's LE prekey layout → BE recurrence view.",
  detail: `## Prekey codec (LE → BE)

Serpent reads the padded key as eight **little-endian** 32-bit prekey words.
The decomposed recurrence runs on **big-endian** words (the
\`rotate-bits-right\` primitive's word view), so this leaf byte-swaps every
4-byte word in place via the per-word permutation \`[3,2,1,0, 7,6,5,4, …]\`.

The body downstream operates uniformly on BE 32-bit words; XOR and the round
constants are byte-wise so order-invariant, but the rotation needs the BE view.
This codec concentrates the endianness adaptation in one explicit place.`,
  references: ["Anderson, Biham, Knudsen 1998, §2 (step 2)"],
};

const NARR_MASTER_SPLIT: StepDocumentation = {
  name: "Split into 8 prekey words",
  summary: "Split the BE-encoded padded key into the eight seed prekey words w₋₈…w₋₁.",
  detail: `## Prekey split

After the input codec, the 32-byte padded key is laid out as eight BE-encoded
32-bit words. This split exposes \`output0 = w₋₈\`, …, \`output7 = w₋₁\` as
individual ports the per-iteration recurrence wires to.`,
  references: ["Anderson, Biham, Knudsen 1998, §2 (step 2)"],
};

const NARR_PHI: StepDocumentation = {
  name: "Constant φ = 0x9e3779b9",
  summary: "The golden-ratio constant XORed into every prekey recurrence step.",
  detail: `## φ = 0x9e3779b9

The fractional part of the golden ratio — Knuth's recommended "random-looking"
constant (also used by Speck and TEA). XORed into every prekey recurrence step
to break symmetry. One shared constant-load leaf fanned out to all 132 XORs.`,
  references: ["Anderson, Biham, Knudsen 1998, §2 (step 3)"],
};

const NARR_ROUND_CONST = (j: number): StepDocumentation => ({
  name: `Round counter ${j}`,
  summary: `The iteration index j = ${j}, XORed into the prekey recurrence.`,
  detail: `## Round counter j = ${j}

Serpent's prekey recurrence XORs the **loop counter** \`j\` (not the array
index) into each step. This constant-load emits the big-endian 32-bit encoding
of \`${j}\` for the XOR below.`,
  references: ["Anderson, Biham, Knudsen 1998, §2 (step 3)"],
});

const NARR_RECUR_XOR: StepDocumentation = {
  name: "w_{i-8} ⊕ w_{i-5} ⊕ w_{i-3} ⊕ w_{i-1} ⊕ φ ⊕ j",
  summary: "The 6-way XOR feeding the prekey rotation.",
  detail: `## Prekey XOR

The six-way XOR that feeds the rotation: four lagged prekey words (lags 8, 5,
3, 1), the golden-ratio constant φ, and the loop counter j. Byte-wise XOR over
the BE word encodings.`,
  references: ["Anderson, Biham, Knudsen 1998, §2 (step 3)"],
};

const NARR_ROL: StepDocumentation = {
  name: "ROL(…, 11)",
  summary: "Left-rotate the XOR result by 11 bits. Implemented as ROR(21) over a 32-bit word.",
  detail: `## ROL(x, 11)

The prekey is the XOR result rotated **left** by 11 bits over a 32-bit word.
Implemented here as a right-rotation by \`32 - 11 = 21\` bits —
\`ROL(x, 11) = ROR(x, 21)\` — so a single \`rotate-bits-right\` primitive
serves it. This is the only byte-order-sensitive op in the recurrence, hence
the BE codec at the input boundary.`,
  references: ["Anderson, Biham, Knudsen 1998, §2 (step 3)"],
};

const NARR_GROUP_CONCAT = (i: number): StepDocumentation => ({
  name: `Assemble group ${i} words`,
  summary: `Concatenate prekey words ${8 + 4 * i}…${8 + 4 * i + 3} for the S-box.`,
  detail: `## Group ${i} words

Concatenate the four prekey words \`w_{${4 * i}}\` … \`w_{${4 * i + 3}}\`
(array indices ${8 + 4 * i} … ${8 + 4 * i + 3}) into one 16-byte buffer — the
input to this group's bitsliced S-box + IP.`,
  references: ["Anderson, Biham, Knudsen 1998, §2 (step 4)"],
});

const NARR_KEY_SBOX = (i: number, sboxIndex: number): StepDocumentation => ({
  name: `Round key ${i}: S${sboxIndex} + IP`,
  summary: `Bitsliced S${sboxIndex} on group ${i}, then IP → round key ${i}.`,
  detail: `## Round key ${i}

Apply the bitsliced forward S-box \`S${sboxIndex}\` to group ${i}'s four prekey
words, then the Initial Permutation, producing the 16-byte round key
\`K_{${i}}\`. The S-box index walks down the table with wraparound:
\`S_{(35 - ${i}) mod 8} = S${sboxIndex}\`. Lifted verbatim from the monolithic
key-expansion so it is byte-identical by construction.`,
  references: ["Anderson, Biham, Knudsen 1998, §2 (steps 4 + 5)"],
});

// ─── Builder ──────────────────────────────────────────────────────────────────

const SERPENT_PREKEY_ITERATIONS = 132;
const SERPENT_ROUND_KEYS = 33;

/**
 * Build the decomposed Serpent key schedule as a single (default-collapsed)
 * `key-schedule` group. Writes `aux["roundKey.0..32"]` via the
 * `serpent.publish-round-keys@1` tail — byte-identical to the legacy
 * `serpent.key-expansion@1` monolith for all three key sizes.
 *
 * @param keyByteLength  16 / 24 / 32 (Serpent-128 / 192 / 256). Selects the
 *                       pad branch; the recurrence + S-box stages are identical.
 */
export function buildSerpentKeyScheduleNative(keyByteLength: 16 | 24 | 32): StepNode {
  if (keyByteLength !== 16 && keyByteLength !== 24 && keyByteLength !== 32) {
    throw new Error(
      `buildSerpentKeyScheduleNative: keyByteLength must be 16, 24, or 32 (got ${keyByteLength})`,
    );
  }

  const children: StepNode[] = [];

  // ── Master-key load (raw memory-order bytes from aux). ────────────────────
  children.push({
    kind: "step",
    id: ks("load-key"),
    type: "aux-load-bytes@1",
    params: { auxName: "key", byteLength: keyByteLength },
    narrationOverride: NARR_LOAD_KEY,
  });

  // ── Pad to 32 bytes (16/24-byte keys only). ───────────────────────────────
  // Append 0x01 then zeros (LSB-first padding "1" bit at position 8*keyLen).
  // The codec below feeds from `padded-output`: the pad concat for short keys,
  // or the load-key output directly for 32-byte keys.
  let paddedOutput: PortBinding;
  if (keyByteLength < 32) {
    const tailLength = 32 - keyByteLength;
    const tailBytes = new Array<number>(tailLength).fill(0);
    tailBytes[0] = 0x01;
    children.push({
      kind: "step",
      id: ks("pad-const"),
      type: "constant-load@1",
      params: { bytes: tailBytes },
      narrationOverride: NARR_PAD_CONST,
    });
    children.push({
      kind: "step",
      id: ks("pad"),
      type: "concat@1",
      params: { inputCount: 2 },
      portInputs: {
        input0: port(ks("load-key"), "output"),
        input1: port(ks("pad-const"), "output"),
      },
      narrationOverride: NARR_PAD,
    });
    paddedOutput = port(ks("pad"), "output");
  } else {
    paddedOutput = port(ks("load-key"), "output");
  }

  // ── Input codec: byte-swap each 32-bit word LE→BE (8 words / 32 bytes). ────
  children.push({
    kind: "step",
    id: ks("input-codec"),
    type: "permute@1",
    params: { indices: wordByteSwapIndices(8) },
    portInputs: { input: paddedOutput },
    narrationOverride: NARR_INPUT_CODEC,
  });

  // ── Master-key split into the 8 seed prekey words w₋₈ … w₋₁. ──────────────
  children.push({
    kind: "step",
    id: ks("master-split"),
    type: "split-bytes@1",
    params: { widths: [4, 4, 4, 4, 4, 4, 4, 4] },
    portInputs: { input: port(ks("input-codec"), "output") },
    narrationOverride: NARR_MASTER_SPLIT,
  });

  // ── Shared φ constant (fanned out to all 132 XORs). ───────────────────────
  children.push({
    kind: "step",
    id: ks("phi"),
    type: "constant-load@1",
    params: { bytes: [...PHI_BE_BYTES] },
    narrationOverride: NARR_PHI,
  });

  // ── 132 unrolled recurrence iterations (loop counter j = 0 … 131). ────────
  // Array index idx = j + 8. Tap prekey index p < 8 → seed word
  // master-split.output{p}; p ≥ 8 → iteration (p-8)'s `new` output.
  const tap = (p: number): PortBinding =>
    p < 8 ? port(ks("master-split"), `output${p}`) : port(ks(`j${p - 8}.new`), "output");

  for (let j = 0; j < SERPENT_PREKEY_ITERATIONS; j++) {
    const id = (leaf: string): string => ks(`j${j}.${leaf}`);
    const idx = j + 8;

    // Per-iteration loop-counter constant (BE32 of j).
    children.push({
      kind: "step",
      id: id("round-const"),
      type: "constant-load@1",
      params: { bytes: j32BE(j) },
      narrationOverride: NARR_ROUND_CONST(j),
    });

    // 6-way XOR: w_{idx-8} ⊕ w_{idx-5} ⊕ w_{idx-3} ⊕ w_{idx-1} ⊕ φ ⊕ j.
    children.push({
      kind: "step",
      id: id("xor"),
      type: "xor@1",
      params: { inputCount: 6 },
      portInputs: {
        operand0: tap(idx - 8),
        operand1: tap(idx - 5),
        operand2: tap(idx - 3),
        operand3: tap(idx - 1),
        operand4: port(ks("phi"), "output"),
        operand5: port(id("round-const"), "output"),
      },
      narrationOverride: NARR_RECUR_XOR,
    });

    // ROL(x, 11) ≡ ROR(x, 21) over a 32-bit word.
    children.push({
      kind: "step",
      id: id("new"),
      type: "rotate-bits-right@1",
      params: { bits: 21, wordBits: 32 },
      portInputs: { input: port(id("xor"), "output") },
      narrationOverride: NARR_ROL,
    });
  }

  // ── 33 round-key groups: concat 4 words → key-sbox (S-box + IP). ──────────
  // Group i uses prekey words 8+4i .. 8+4i+3, i.e. iterations 4i .. 4i+3.
  const publishInputs: Record<string, PortBinding> = {};
  for (let i = 0; i < SERPENT_ROUND_KEYS; i++) {
    const base = 4 * i; // iteration index of the group's first word
    const concatId = ks(`group-${i}.concat`);
    children.push({
      kind: "step",
      id: concatId,
      type: "concat@1",
      params: { inputCount: 4 },
      portInputs: {
        input0: port(ks(`j${base}.new`), "output"),
        input1: port(ks(`j${base + 1}.new`), "output"),
        input2: port(ks(`j${base + 2}.new`), "output"),
        input3: port(ks(`j${base + 3}.new`), "output"),
      },
      narrationOverride: NARR_GROUP_CONCAT(i),
    });

    // S-box index walks down the table with wraparound: (35 - i) mod 8.
    const sboxIndex = (((35 - i) % 8) + 8) % 8;
    const sboxId = ks(`group-${i}.sbox`);
    children.push({
      kind: "step",
      id: sboxId,
      type: "serpent.key-sbox@1",
      params: { sboxIndex },
      portInputs: { input: port(concatId, "output") },
      narrationOverride: NARR_KEY_SBOX(i, sboxIndex),
    });
    publishInputs[`key${i}`] = port(sboxId, "output");
  }

  // ── Publish tail (the one surviving meta): aux["roundKey.0..32"]. ─────────
  children.push({
    kind: "step",
    id: ks("publish"),
    type: "serpent.publish-round-keys@1",
    params: { outputPrefix: "roundKey", count: SERPENT_ROUND_KEYS },
    portInputs: publishInputs,
  });

  return {
    kind: "group",
    id: "key-schedule",
    label: "Key Expansion",
    // Default-collapse so the ~400 recurrence chips don't wall the canvas on
    // first graph render (same posture as AES/Speck decomposed schedules).
    defaultCollapsed: true,
    children,
  };
}
