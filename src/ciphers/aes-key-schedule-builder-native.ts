/**
 * Byte-native AES key-schedule construction — key-schedule-decomposition plan
 * Slice K1a (2026-06-01). The port-native replacement for the monolithic
 * `aes.key-expansion@1/@2` executor.
 *
 * **Why decompose.** The monolith ran the whole FIPS-197 §5.2 expansion
 * (RotWord / SubWord / Rcon / word-XOR) inside ONE executor — invisible to the
 * trace. This builder expresses the same math as a tree of port-native
 * primitives so every sub-step is a scrubbable frame, the same way the
 * `aes-round-builder-native.ts` round body and SHA-256's compression rounds
 * already are.
 *
 * **Why unroll, not iterate (advisor-confirmed 2026-06-01).** AES's key
 * schedule has a PER-GROUP constant (Rcon[g]), so it is structurally a sibling
 * of SHA-256's UNROLLED rounds (each a group with its own constant), NOT its
 * FES message schedule (a uniform body with no per-iteration constant). A
 * shared FES body cannot carry a per-iteration constant, so we unroll the
 * Nk-word recurrence groups, each carrying its own editable `constant-load@1`
 * Rcon. Duplicate-round stays correct because `bumpKeyExpansion` rebuilds the
 * subgraph via this builder at the new round count (Slice K1b) — the structure
 * being unrolled is irrelevant to that.
 *
 * **B-minimal (producer-only).** The recurrence is visible; a single
 * meta-bearing `aes.publish-round-keys@1` tail writes `aux["roundKey.0..N"]`
 * byte-identically to the monolith, so the round-body consumers
 * (`xor-with-aux@1`) and `aes-round-builder-native.ts` are UNTOUCHED.
 *
 * **The Nk recurrence (FIPS-197 §5.2).** With `Nk = key.byteLength / 4` words
 * in the master key and `totalWords = 4·(Nr+1)` words total, words are derived
 * one Nk-word GROUP at a time. Within generated group `g` (words
 * `g·Nk … g·Nk+Nk-1`):
 *   - word 0 (`i % Nk == 0`): temp = SubWord(RotWord(prev group's last word))
 *     XOR Rcon[g]; new word = (prev group's word 0) XOR temp.
 *   - word j (1..Nk-1): new word = (prev group's word j) XOR (this group's
 *     word j-1). For AES-256 (`Nk == 8`) at j == 4 an extra SubWord is applied
 *     to (word 3) first — the FIPS-197 §5.2 mid-word SubWord, no RotWord/Rcon.
 * The previous group's words arrive as that group's concatenated `out`; the
 * very first group reads the master key (group 0). Groups don't align with
 * 16-byte round keys for Nk=6/8, so a separate repack concatenates the whole
 * word stream and `byte-slice`s out each round key.
 *
 * AES-variant agnostic via (rounds, Nk): AES-128 (10,4) → 44 words / 10 full
 * groups; AES-192 (12,6) → 52 words / 7 full + 1 partial(4); AES-256 (14,8) →
 * 60 words / 6 full + 1 partial(4), with the j==4 SubWord in each full group.
 */

import type { PortBinding, StepDocumentation, StepNode } from "../core/types";
import { AES_RCON, AES_SBOX } from "./aes-constants";

// ─── PortBinding + name helpers ───────────────────────────────────────────────

const port = (node: string, portName: string): PortBinding => ({ node, port: portName });
const ks = (suffix: string): string => `key-schedule.${suffix}`;
/** RotWord = cyclic LEFT rotation of a 4-byte word by one byte. As a gather
 *  permutation (`out[i] = in[indices[i]]`) that is `[1,2,3,0]`. */
const ROTWORD_INDICES: readonly number[] = [1, 2, 3, 0];

// ─── Build-time Rcon (FIPS-197 §5.2) ──────────────────────────────────────────
// Rcon[g] = x^(g-1) in GF(2^8); the round constant XORed into byte 0 of each
// group's first word. Computed at BUILD time (not wired as a runtime table) and
// extended past the canonical AES_RCON seed via the xtime recurrence so
// duplicate-round's larger round counts (Slice K1b) get correct constants for
// free.

/** Multiply by x in GF(2^8) with reduction polynomial 0x11b. */
const xtime = (n: number): number => {
  const shifted = (n << 1) & 0xff;
  return (n & 0x80) === 0 ? shifted : shifted ^ 0x1b;
};

/** Rcon byte for generated group `g` (g ≥ 1). Honors the canonical AES_RCON
 *  seed (indices 1..10) and extends via xtime beyond it. */
const rconByte = (g: number): number => {
  if (g >= 1 && g < AES_RCON.length) return AES_RCON[g] ?? 0;
  // Extend from the last canonical entry (AES_RCON[10] = 0x36).
  let v = AES_RCON[AES_RCON.length - 1] ?? 0;
  for (let i = AES_RCON.length - 1; i < g; i++) v = xtime(v);
  return v;
};

// ─── narrationOverride docs (FIPS-197 §5.2 friendly names) ────────────────────
// One shared static doc per role (the op is identical every group; the
// per-group specifics are the frame's byte values). Mirrors the SHA-256 /
// round-body narration idiom.

const NARR_LOAD_KEY: StepDocumentation = {
  name: "Load cipher key",
  summary: "Load the Nk-word master key from aux to seed the key schedule.",
  detail: `## Load cipher key

The master key (16 / 24 / 32 bytes for AES-128 / 192 / 256) is the first
\`Nk\` words of the expanded key — group 0 of the recurrence. Every later
group is derived from the one before it; this leaf supplies the starting
group and also feeds the final round-key repack.`,
  references: ["FIPS-197 §5.2 (Key Expansion)"],
};

const NARR_SPLIT: StepDocumentation = {
  name: "Split previous group into words",
  summary: "Split the previous Nk-word group into its individual 4-byte words.",
  detail: `## Split into words

Each derived group reads the previous group's \`Nk\` words. \`output{j}\`
carries the previous group's word \`j\`; the recurrence uses word \`Nk-1\`
(for RotWord) and word \`j\` (as the \`w[i-Nk]\` term of new word \`j\`).`,
  references: ["FIPS-197 §5.2"],
};

const NARR_ROTWORD: StepDocumentation = {
  name: "RotWord",
  summary: "Cyclically rotate the previous word's bytes left by one (FIPS-197 §5.2).",
  detail: `## RotWord

\`RotWord([a,b,c,d]) = [b,c,d,a]\` — a one-byte cyclic left rotation,
applied to the previous group's last word before it enters SubWord. Only
the first word of each group passes through RotWord.`,
  references: ["FIPS-197 §5.2 (RotWord)"],
};

const NARR_SUBWORD: StepDocumentation = {
  name: "SubWord",
  summary: "Apply the AES S-box to each byte of the word (FIPS-197 §5.2).",
  detail: `## SubWord

Each byte of the (rotated) word is replaced by \`sbox[b]\`, the **forward**
AES S-box — even when decrypting (the inverse cipher reuses these same round
keys in reverse order; it does not re-derive them with the inverse S-box).
SubWord is what makes the key schedule non-linear.`,
  references: ["FIPS-197 §5.2 (SubWord)", "FIPS-197 §5.1.1 (S-box)"],
};

const NARR_SUBWORD_MID: StepDocumentation = {
  name: "SubWord (AES-256 mid-word)",
  summary: "Extra SubWord at i % Nk == 4 for AES-256 — no RotWord, no Rcon (FIPS-197 §5.2).",
  detail: `## SubWord (AES-256 only)

For AES-256 (\`Nk = 8\`), the word at \`i % Nk == 4\` gets an extra SubWord
pass with **no** RotWord and **no** Rcon. This branch fires only for AES-256;
AES-128 and AES-192 never reach it.`,
  references: ["FIPS-197 §5.2 (Nk > 6 branch)"],
};

const NARR_RCON: StepDocumentation = {
  name: "Rcon constant",
  summary: "The round constant Rcon[g] = x^(g-1) in GF(2⁸), in byte 0 (FIPS-197 §5.2).",
  detail: `## Rcon

The round constant for this group: \`[Rcon[g], 0, 0, 0]\` where
\`Rcon[g] = x^(g-1)\` in GF(2⁸) (1, 2, 4, 8, …, 0x1b, 0x36, …). It is XORed
into byte 0 of the post-SubWord word. Editable per group — change it and the
schedule (and ciphertext) diverge.`,
  references: ["FIPS-197 §5.2 (Rcon)"],
};

const NARR_RCON_XOR: StepDocumentation = {
  name: "XOR Rcon",
  summary: "XOR the round constant into the SubWord output (FIPS-197 §5.2).",
  detail: `## temp = SubWord(RotWord(w[i-1])) ⊕ Rcon[g]

Combines the non-linear SubWord output with this group's round constant to
form the \`temp\` value that seeds the group's first new word.`,
  references: ["FIPS-197 §5.2"],
};

const NARR_WORD_FIRST: StepDocumentation = {
  name: "w[i] = w[i-Nk] ⊕ temp",
  summary: "First word of the group: XOR the matching previous-group word with temp.",
  detail: `## First word of the group

\`w[i] = w[i-Nk] ⊕ temp\`, where \`temp\` is the
\`SubWord(RotWord(w[i-1])) ⊕ Rcon[g]\` value and \`w[i-Nk]\` is the previous
group's word 0. This is the only word in the group touched by RotWord /
SubWord / Rcon.`,
  references: ["FIPS-197 §5.2"],
};

const NARR_WORD_PLAIN: StepDocumentation = {
  name: "w[i] = w[i-Nk] ⊕ w[i-1]",
  summary: "A plain schedule word: XOR the matching previous-group word with the prior word.",
  detail: `## Plain schedule word

\`w[i] = w[i-Nk] ⊕ w[i-1]\` — the common case. \`w[i-Nk]\` is the previous
group's word at this position; \`w[i-1]\` is the word just computed in this
group. No RotWord / SubWord / Rcon.`,
  references: ["FIPS-197 §5.2"],
};

const NARR_WORD_MID: StepDocumentation = {
  name: "w[i] = w[i-Nk] ⊕ SubWord(w[i-1])",
  summary: "AES-256 mid-word: XOR the previous-group word with the SubWord'd prior word.",
  detail: `## AES-256 mid-word

For AES-256 at \`i % Nk == 4\`: \`w[i] = w[i-Nk] ⊕ SubWord(w[i-1])\` — the
extra SubWord (no RotWord, no Rcon) applied to the immediately preceding word.`,
  references: ["FIPS-197 §5.2 (Nk > 6 branch)"],
};

const NARR_GROUP_OUT: StepDocumentation = {
  name: "Assemble group words",
  summary: "Concatenate this group's words so the next group can read them.",
  detail: `## Assemble group

Concatenates this group's freshly derived words into one buffer — the input
the next group splits, and one of the inputs to the final round-key repack.`,
  references: ["FIPS-197 §5.2"],
};

const NARR_WORD_STREAM: StepDocumentation = {
  name: "Assemble full word stream",
  summary: "Concatenate the master key and every derived group into the full expanded key.",
  detail: `## Full expanded key

Concatenates the master key (group 0) with every derived group, producing the
complete \`4·(Nr+1)\`-word expanded key. The next leaves slice 16-byte round
keys out of this stream (groups and round keys don't align for AES-192/256,
so the slice happens here rather than per group).`,
  references: ["FIPS-197 §5.2"],
};

const NARR_ROUND_KEY: StepDocumentation = {
  name: "Slice round key",
  summary: "Extract one 16-byte round key from the expanded-key word stream.",
  detail: `## Round key r

Round key \`r\` is the 16 bytes at offset \`16·r\` in the expanded-key word
stream — words \`4r … 4r+3\`. The AddRoundKey steps read these (via the
publish tail's aux entries) one per round.`,
  references: ["FIPS-197 §5.2", "FIPS-197 §5.1.4 (AddRoundKey)"],
};

// ─── Builder ──────────────────────────────────────────────────────────────────

/**
 * Build the decomposed AES key schedule as a single (default-collapsed)
 * `key-schedule` group. Writes `aux["roundKey.0".."roundKey.{rounds}"]` via
 * the `aes.publish-round-keys@1` tail — byte-identical to the monolith.
 *
 * @param rounds  Nr (10 / 12 / 14 for AES-128 / 192 / 256; any ≥ 1 for the
 *                duplicate-round rebuild).
 * @param nk      Nk = master-key words (4 / 6 / 8). Derive as
 *                `key.byteLength / 4` at the call site.
 */
export function buildAesKeyScheduleNative(rounds: number, nk: number): StepNode {
  if (!Number.isInteger(rounds) || rounds < 1) {
    throw new Error(`buildAesKeyScheduleNative: rounds must be a positive integer (got ${rounds})`);
  }
  if (nk !== 4 && nk !== 6 && nk !== 8) {
    throw new Error(`buildAesKeyScheduleNative: Nk must be 4, 6, or 8 (got ${nk})`);
  }
  const totalWords = 4 * (rounds + 1);
  const generated = totalWords - nk;
  if (generated < 1) {
    throw new Error(
      `buildAesKeyScheduleNative: rounds ${rounds} too small for Nk ${nk} (no words to derive)`,
    );
  }
  const numFullGroups = Math.floor(generated / nk);
  const remainder = generated % nk;
  const numGroups = numFullGroups + (remainder > 0 ? 1 : 0);

  const children: StepNode[] = [];

  // ── Group 0: the master key, loaded from aux["key"]. ──────────────────────
  children.push({
    kind: "step",
    id: ks("load-key"),
    type: "aux-load-bytes@1",
    params: { auxName: "key", byteLength: nk * 4 },
    narrationOverride: NARR_LOAD_KEY,
  });

  // ── Generated groups 1 … numGroups. ───────────────────────────────────────
  for (let g = 1; g <= numGroups; g++) {
    const wordsInGroup = g <= numFullGroups ? nk : remainder;
    const gp = `g${g}`;
    const id = (leaf: string): string => ks(`${gp}.${leaf}`);
    // Previous group's concatenated words: group 0 = the master key; otherwise
    // the prior group's `out`. (The partial group is always LAST, so a
    // predecessor is always a full Nk-word group.)
    const prevBuf = g === 1 ? port(ks("load-key"), "output") : port(ks(`g${g - 1}.out`), "output");

    // Split the previous group's Nk words apart.
    children.push({
      kind: "step",
      id: id("split"),
      type: "split-bytes@1",
      params: { widths: Array.from({ length: nk }, () => 4) },
      portInputs: { input: prevBuf },
      narrationOverride: NARR_SPLIT,
    });

    // First word: temp = SubWord(RotWord(prev word Nk-1)) ⊕ Rcon[g];
    //             w[0] = (prev word 0) ⊕ temp.
    children.push({
      kind: "step",
      id: id("rotword"),
      type: "permute@1",
      params: { indices: [...ROTWORD_INDICES] },
      portInputs: { input: port(id("split"), `output${nk - 1}`) },
      narrationOverride: NARR_ROTWORD,
    });
    children.push({
      kind: "step",
      id: id("subword"),
      type: "byte-substitute@1",
      params: { sbox: [...AES_SBOX] },
      portInputs: { input: port(id("rotword"), "output") },
      narrationOverride: NARR_SUBWORD,
    });
    children.push({
      kind: "step",
      id: id("rcon"),
      type: "constant-load@1",
      params: { bytes: [rconByte(g), 0, 0, 0] },
      narrationOverride: NARR_RCON,
    });
    children.push({
      kind: "step",
      id: id("temp"),
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: port(id("subword"), "output"),
        operand1: port(id("rcon"), "output"),
      },
      narrationOverride: NARR_RCON_XOR,
    });
    children.push({
      kind: "step",
      id: id("w0"),
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: port(id("split"), "output0"),
        operand1: port(id("temp"), "output"),
      },
      narrationOverride: NARR_WORD_FIRST,
    });

    // Remaining words j = 1 … wordsInGroup-1.
    for (let j = 1; j < wordsInGroup; j++) {
      if (nk === 8 && j === 4) {
        // AES-256 mid-word: SubWord(w[i-1]) with no RotWord / Rcon.
        children.push({
          kind: "step",
          id: id("subword4"),
          type: "byte-substitute@1",
          params: { sbox: [...AES_SBOX] },
          portInputs: { input: port(id(`w${j - 1}`), "output") },
          narrationOverride: NARR_SUBWORD_MID,
        });
        children.push({
          kind: "step",
          id: id(`w${j}`),
          type: "xor@1",
          params: { inputCount: 2 },
          portInputs: {
            operand0: port(id("split"), `output${j}`),
            operand1: port(id("subword4"), "output"),
          },
          narrationOverride: NARR_WORD_MID,
        });
      } else {
        children.push({
          kind: "step",
          id: id(`w${j}`),
          type: "xor@1",
          params: { inputCount: 2 },
          portInputs: {
            operand0: port(id("split"), `output${j}`),
            operand1: port(id(`w${j - 1}`), "output"),
          },
          narrationOverride: NARR_WORD_PLAIN,
        });
      }
    }

    // Concatenate the group's words so the next group can split them.
    const outInputs: Record<string, PortBinding> = {};
    for (let j = 0; j < wordsInGroup; j++) {
      outInputs[`input${j}`] = port(id(`w${j}`), "output");
    }
    children.push({
      kind: "step",
      id: id("out"),
      type: "concat@1",
      params: { inputCount: wordsInGroup },
      portInputs: outInputs,
      narrationOverride: NARR_GROUP_OUT,
    });
  }

  // ── Repack: master key ++ every group → full word stream → 16-byte keys. ──
  const streamInputs: Record<string, PortBinding> = {
    input0: port(ks("load-key"), "output"),
  };
  for (let g = 1; g <= numGroups; g++) {
    streamInputs[`input${g}`] = port(ks(`g${g}.out`), "output");
  }
  children.push({
    kind: "step",
    id: ks("word-stream"),
    type: "concat@1",
    params: { inputCount: numGroups + 1 },
    portInputs: streamInputs,
    narrationOverride: NARR_WORD_STREAM,
  });

  const sourceByteLength = totalWords * 4;
  for (let r = 0; r <= rounds; r++) {
    children.push({
      kind: "step",
      id: ks(`rk${r}`),
      type: "byte-slice@1",
      params: { sourceByteLength, offset: 16 * r, length: 16 },
      portInputs: { input: port(ks("word-stream"), "output") },
      narrationOverride: NARR_ROUND_KEY,
    });
  }

  // ── Publish tail (the one surviving meta): aux["roundKey.0..N"]. ──────────
  const publishInputs: Record<string, PortBinding> = {};
  for (let r = 0; r <= rounds; r++) {
    publishInputs[`key${r}`] = port(ks(`rk${r}`), "output");
  }
  children.push({
    kind: "step",
    id: ks("publish"),
    type: "aes.publish-round-keys@1",
    params: { outputPrefix: "roundKey", rounds },
    portInputs: publishInputs,
  });

  return {
    kind: "group",
    id: "key-schedule",
    label: "Key Expansion",
    // Default-collapse so the ~100+ recurrence chips don't wall the canvas on
    // first graph render (same posture as SHA-256's rounds / message schedule).
    defaultCollapsed: true,
    children,
  };
}
