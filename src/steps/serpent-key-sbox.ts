/**
 * Serpent key-schedule S-box leaf — key-schedule-decomposition plan slice K3a
 * (2026-06-02). The dedicated, port-native lift of the Serpent key schedule's
 * "bitsliced S-box + IP" stage (steps 4 + 5 of `serpent.key-expansion@1`).
 *
 * **Why a dedicated step type, not reuse `serpent.sub-bytes@1`.** The round
 * body's `serpent.sub-bytes@1` carries a cross-mode mirror role (forward S-box
 * on encrypt, inverse on decrypt) and operates on the IP'd state domain. The
 * key schedule's S-box is structurally different: it applies the FORWARD
 * bitsliced S-box to the four RAW prekey words of a group and THEN applies IP
 * to the result — it is verified-by-construction the same operation the
 * monolithic key-expansion executor performs, lifted EXACTLY. Reusing
 * `serpent.sub-bytes@1` would force mirror role-scoping work we deliberately
 * avoid by giving the schedule its own S-box step (the K3 advisor pick:
 * option B).
 *
 * **Byte-order (matches the decomposed builder's BE recurrence).** The
 * decomposed schedule runs the prekey recurrence on BIG-ENDIAN-encoded 32-bit
 * words (the `rotate-bits-right@1` primitive reads/writes BE words, so the
 * builder byte-swaps the LE master key into BE once at the input codec). This
 * leaf therefore decodes its 16-byte input as four BE 32-bit words via
 * `decodeBE32` — the exact codec `rotate-bits-right@1` uses. After the S-box,
 * `wordsToBytes4` (little-endian) and `applyBitPermutation(SERPENT_IP)` are
 * lifted VERBATIM from the oracle, so the output is byte-identical to the
 * monolith's per-round-key bytes. The only byte-order decision is the INPUT
 * decode; everything downstream of `sboxBitslice4` is verbatim oracle code in
 * the number domain → LE serialize → IP.
 *
 * Contract: one raw input port `input` (16 bytes = the 4 BE prekey words of one
 * group) → one raw output port `output` (the 16-byte raw-then-IP'd round key).
 * Pure port-native: `kind:"ported"`, no `meta`, no `legacy`, no `shapeContract`.
 *
 * params: { sboxIndex: 0..7 } — selects `SERPENT_SBOXES[sboxIndex]`. The
 * builder computes the index per group as `(((35 - i) % 8) + 8) % 8`.
 */

import { SERPENT_IP, SERPENT_SBOXES } from "../ciphers/serpent-constants";
import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { decodeBE32 } from "../core/word-codec";
import { applyBitPermutation, sboxBitslice4, wordsToBytes4 } from "./serpent-bit-ops";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly sboxIndex: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("serpent.key-sbox: params must be an object");
  }
  const p = params as Record<string, Json>;
  const sboxIndex = p.sboxIndex;
  if (
    typeof sboxIndex !== "number" ||
    !Number.isInteger(sboxIndex) ||
    sboxIndex < 0 ||
    sboxIndex > 7
  ) {
    throw new Error("serpent.key-sbox: params.sboxIndex must be an integer in [0, 7]");
  }
  return { sboxIndex };
};

// ─── Port contract + executor ─────────────────────────────────────────────

export const serpentKeySboxPortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const serpentKeySbox: PortedExecutor = (inputs, params, _ctx) => {
  const { sboxIndex } = readParams(params);
  const input = inputs.get("input");
  if (!(input instanceof Uint8Array)) {
    throw new Error(
      "serpent.key-sbox: input port 'input' must carry the 4 prekey words (16 bytes)",
    );
  }
  if (input.length !== 16) {
    throw new Error(
      `serpent.key-sbox: input must be 16 bytes (4 prekey words); got ${input.length}`,
    );
  }

  // Decode as four BIG-ENDIAN 32-bit words — matches the decomposed builder's
  // BE recurrence (the rotate-bits-right@1 primitive reads/writes BE words).
  const w0 = decodeBE32(input, 0);
  const w1 = decodeBE32(input, 4);
  const w2 = decodeBE32(input, 8);
  const w3 = decodeBE32(input, 12);

  const sbox = SERPENT_SBOXES[sboxIndex] ?? [];
  const [k0, k1, k2, k3] = sboxBitslice4(w0, w1, w2, w3, sbox);

  // ── Verbatim oracle steps 4 + 5 ──────────────────────────────────────────
  // wordsToBytes4 serializes LE; applyBitPermutation(IP) then permutes the
  // bits in that LE byte/bit domain. Lifted EXACTLY from
  // serpent-key-expansion.ts so the output is byte-identical to the monolith.
  const rawRoundKey = wordsToBytes4(k0, k1, k2, k3);
  const permutedRoundKey = applyBitPermutation(rawRoundKey, SERPENT_IP);
  return new Map([["output", permutedRoundKey]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const serpentKeySboxDoc: StepDocumentation = {
  name: "Key S-box + IP (Serpent)",
  summary:
    "Apply the bitsliced forward S-box to one group of 4 prekey words, then IP — producing one raw round key.",
  detail: `## Key S-box + IP (Serpent)

The Serpent key schedule turns the 132 generated prekey words into 33 round
keys by grouping them into 33 sets of four consecutive words and applying a
**bitsliced 4-bit S-box** to each group, then the **Initial Permutation (IP)**.

### What this leaf does

1. **Read** the 16-byte input as four 32-bit words.

2. **Bitsliced S-box.** For each of the 32 bit-columns across the four words,
   the 4 bits (one per word) form a nibble, which is looked up in the chosen
   Serpent S-box and written back to the same column. The S-box index walks
   **down** the eight-box list with wraparound: group \`i\` uses
   \`S_{(35 - i) mod 8}\` (group 0 → S₃, group 1 → S₂, …).

3. **IP.** The raw round key is passed through the Initial Permutation so it
   lines up bit-for-bit with the IP'd state inside the round body — both
   operands of the AddRoundKey XOR live in the permuted domain.

This is the FORWARD S-box even when decrypting: the key schedule is identical
for encrypt and decrypt; only the consumption order of the 33 round keys
differs. So unlike the round body's SubBytes, this leaf carries no cross-mode
mirror.`,
  params: new Map([
    ["sboxIndex", "Which of the 8 Serpent S-boxes to apply (0–7) for this group of prekey words."],
  ]),
  references: [
    "Anderson, Biham, Knudsen 1998, §2 (Key Schedule, steps 4 + 5)",
    "Serpent NIST submission, tstsubmtl/serpref.c (makeKey() function)",
  ],
  // No `shapeContract` — port-native steps describe their surface via the
  // PortContract instead.
};
