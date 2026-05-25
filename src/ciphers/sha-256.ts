/**
 * SHA-256 cipher spec — first port-native cipher under the universal-port
 * dataflow plan. Rewritten in Slice 2.6d (2026-05-25) using decomposed
 * port-native compositions of the universal vocabulary (rotate-bits-right,
 * shift-bits-right, xor, add-mod-32, and, not, concat, split-bytes,
 * byte-slice, aux-load-bytes, constant-load, state-to-bytes, bytes-to-state)
 * + the existing `generic.state-to-aux@1` bridge — no more
 * SHA-256-specific helper steps in the spec.
 *
 * **Topology overview (Slice 2.6d, user picks 2026-05-25):**
 *
 * ```
 * 1.  state-to-bytes "plaintext-source"   → output = plaintext bytes
 * 2.  pad-with-byte "pad"                  → output = padded bytes
 *                                            (msg + 0x80 + zeros to ≡ 56 mod 64)
 * 3.  append-be64-length "length-append"   → output = 64-byte padded block
 *                                            (single-block "abc")
 * 4.  bytes-to-state "seed-schedule"       → state = padded block (64 bytes)
 * 5.  for-each-subgraph-with-history "msg-schedule" → state = W (256 bytes)
 *       body (14 leaves per iteration): aux-load-bytes ×4 (prior-2/-7/-15/-16)
 *                                       + σ1 chain (2 ROTR + 1 SHR + 1 XOR)
 *                                       + σ0 chain (2 ROTR + 1 SHR + 1 XOR)
 *                                       + 4-way add-mod-32 (W_t)
 *                                       + bytes-to-state (FES body exit)
 *       iterationCount=48, lookbackOffsets=[2,7,15,16], entryLen=4
 * 6.  state-to-aux "W-publish"             → aux["W"] = W (256 bytes)
 *                                            [Q1 = (b): W lives in aux from
 *                                            here on, not in state]
 * 7.  aux-load "K-to-aux"                  → aux["K"] = K_0..K_63 (256 bytes)
 * 8.  aux-load "H-to-aux"                  → aux["H"] = H_0..H_7 (32 bytes,
 *                                            used by final-add)
 * 9.  constant-load "H-constant"           → output = H_0..H_7 (32 bytes)
 * 10. bytes-to-state "init-working-vars"   → state = working_vars (32 bytes)
 * 11. (× 64) group "round.t":              28 leaves per round
 *       state-to-bytes → split-bytes(×8 widths=4)
 *       aux-load-bytes K + byte-slice K_t
 *       aux-load-bytes W + byte-slice W_t
 *       Σ1(e): 3 × rotate-bits-right(2,11,25) + xor 3-way
 *       Σ0(a): 3 × rotate-bits-right(6,13,22) + xor 3-way   [the constants
 *         look swapped vs. the prose — see math comments below: lowercase
 *         is Σ0(a)=ROTR2⊕ROTR13⊕ROTR22; uppercase Σ1(e)=ROTR6⊕ROTR11⊕ROTR25.
 *         Per FIPS 180-4 §4.1.2]
 *       Ch(e,f,g): not(e) + and(e,f) + and(¬e,g) + xor 2-way
 *       Maj(a,b,c): and(a,b) + and(a,c) + and(b,c) + xor 3-way
 *       T1 = h + Σ1(e) + Ch(e,f,g) + K_t + W_t (5-way add-mod-32)
 *       T2 = Σ0(a) + Maj(a,b,c) (2-way add-mod-32)
 *       new_a = T1 + T2 (2-way add-mod-32)
 *       new_e = d + T1 (2-way add-mod-32)
 *       Repack: concat 8-way(new_a, a, b, c, new_e, e, f, g)
 *                                  → bytes-to-state (32 bytes)
 *
 *       Renames are FREE: the next round's `a..h` are this round's
 *       (new_a, a, b, c, new_e, e, f, g) — i.e., the working variables
 *       cascade DOWN one slot, with new_a entering at position 0 and h
 *       falling off the end. This is what the 8-way concat encodes.
 * 12. final-add (13 leaves):
 *       state-to-bytes → split-bytes(×8) → a..h
 *       aux-load-bytes "fetch-H" → split-bytes(×8) → H_0..H_7
 *       × 8 add-mod-32 2-way: s_i = a_i + H_i
 *       concat 8-way → 32-byte hash
 *       bytes-to-state (final cipher state)
 * ```
 *
 * **Single-block scope.** This spec assumes the message fits in ONE
 * 64-byte block (after padding + length-suffix). The "abc" KAT (FIPS
 * 180-4 §A.1) is the canonical reference for single-block. Multi-block
 * support (per-block outer loop, running hash threaded across blocks)
 * is deferred to Slice 2.11's KAT matrix.
 *
 * **Math byte-identical to FIPS 180-4.** The "abc" KAT continues to pass
 * after the rewrite — the decomposition is algebraically identical to
 * the helpers it replaces. `tests/sha-256.test.ts` is the load-bearing
 * safety net for this; the decomposition-parity test in
 * `tests/sha-256-decomposition-parity.test.ts` (Slice 2.6d step 5) adds
 * frame-level structural assertions on top.
 *
 * **Frame count grows substantially.** From 123 frames per run (2.6b's
 * coarse helpers) to ~2486 per run (decomposed). Every algorithmic
 * sub-step is now individually visible in the trace, with provenance
 * traceable through each port-native primitive's contract. Pedagogy
 * payoff: the math IS the cipher — students see every ROTR, every XOR,
 * every modular add making up Σ0/Σ1/Ch/Maj/T1/T2.
 *
 * **References:**
 *   - FIPS 180-4 §5.1.1 — Preprocessing (padding + length suffix)
 *   - FIPS 180-4 §5.3.3 — Initial hash values H_0..H_7
 *   - FIPS 180-4 §4.2.2 — Round constants K_0..K_63
 *   - FIPS 180-4 §4.1.2 — Σ0/Σ1/σ0/σ1/Ch/Maj definitions
 *   - FIPS 180-4 §6.2.2 — Single-block message hash computation
 *   - FIPS 180-4 §A.1   — KAT for the 3-byte message "abc"
 *   - docs/plans/universal-port-phase-2-slices.md (Slice 2.6c design +
 *     Slice 2.6d implementation)
 */

import type { CipherSpec, StepNode } from "../core/types";

// ─── SHA-256 constants (FIPS 180-4 §4.2.2 + §5.3.3) ───────────────────────

/**
 * SHA-256 round constants K_0..K_63 — first 32 bits of the fractional
 * parts of the cube roots of the first 64 primes (per FIPS 180-4 §4.2.2).
 * Loaded into `aux["K"]` once at the start of the cipher via
 * `generic.aux-load@1`; each compression round reads its K_t slice from
 * offset `4*t` within aux["K"].
 */
const SHA256_K_WORDS: readonly number[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/**
 * SHA-256 initial hash values H_0..H_7 — first 32 bits of the fractional
 * parts of the square roots of the first 8 primes (per FIPS 180-4 §5.3.3).
 * Used twice: (1) to seed the working variables before compression
 * (constant-load → bytes-to-state), (2) as the per-word addend in the
 * final-add step (aux["H"], read via aux-load-bytes + split-bytes).
 */
const SHA256_H_WORDS: readonly number[] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const wordsToBytes = (words: readonly number[]): number[] => {
  const out = new Array<number>(words.length * 4);
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as number;
    out[i * 4 + 0] = (w >>> 24) & 0xff;
    out[i * 4 + 1] = (w >>> 16) & 0xff;
    out[i * 4 + 2] = (w >>> 8) & 0xff;
    out[i * 4 + 3] = w & 0xff;
  }
  return out;
};

const SHA256_K_BYTES = wordsToBytes(SHA256_K_WORDS); // 256 bytes
const SHA256_H_BYTES = wordsToBytes(SHA256_H_WORDS); // 32 bytes

// ─── Helper: shared port-input shapes (DRY) ───────────────────────────────

const port = (node: string, port: string): { readonly node: string; readonly port: string } => ({
  node,
  port,
});

// ─── Schedule body: 14 leaves per FES iteration ──────────────────────────
//
// Implements σ0/σ1 per FIPS 180-4 §4.1.2 + W_t = σ1(W_{t-2}) + W_{t-7}
// + σ0(W_{t-15}) + W_{t-16} per §6.2.2. The four lookback values come
// from aux["prior-N"] (auto-published by the FES-with-history runtime
// based on `lookbackOffsets=[2,7,15,16]`).
//
// Body exit state must be exactly `historyEntryByteLength = 4` bytes
// (the FES contract validates this). The final `bytes-to-state` leaf
// satisfies that.

const buildScheduleBody = (): readonly StepNode[] => [
  // ── Lookback fetches (4 leaves) ────────────────────────────────────
  {
    kind: "step",
    id: "fetch-p2",
    type: "aux-load-bytes@1",
    params: { auxName: "prior-2", byteLength: 4 },
  },
  {
    kind: "step",
    id: "fetch-p7",
    type: "aux-load-bytes@1",
    params: { auxName: "prior-7", byteLength: 4 },
  },
  {
    kind: "step",
    id: "fetch-p15",
    type: "aux-load-bytes@1",
    params: { auxName: "prior-15", byteLength: 4 },
  },
  {
    kind: "step",
    id: "fetch-p16",
    type: "aux-load-bytes@1",
    params: { auxName: "prior-16", byteLength: 4 },
  },
  // ── σ1(W_{t-2}) = ROTR^17(W_{t-2}) ⊕ ROTR^19(W_{t-2}) ⊕ SHR^10(W_{t-2}) ─
  {
    kind: "step",
    id: "sigma1-r17",
    type: "rotate-bits-right@1",
    params: { wordBits: 32, bits: 17 },
    portInputs: { input: port("fetch-p2", "output") },
  },
  {
    kind: "step",
    id: "sigma1-r19",
    type: "rotate-bits-right@1",
    params: { wordBits: 32, bits: 19 },
    portInputs: { input: port("fetch-p2", "output") },
  },
  {
    kind: "step",
    id: "sigma1-s10",
    type: "shift-bits-right@1",
    params: { wordBits: 32, bits: 10 },
    portInputs: { input: port("fetch-p2", "output") },
  },
  {
    kind: "step",
    id: "sigma1",
    type: "xor@1",
    params: { inputCount: 3 },
    portInputs: {
      operand0: port("sigma1-r17", "output"),
      operand1: port("sigma1-r19", "output"),
      operand2: port("sigma1-s10", "output"),
    },
  },
  // ── σ0(W_{t-15}) = ROTR^7(W_{t-15}) ⊕ ROTR^18(W_{t-15}) ⊕ SHR^3(W_{t-15}) ─
  {
    kind: "step",
    id: "sigma0-r7",
    type: "rotate-bits-right@1",
    params: { wordBits: 32, bits: 7 },
    portInputs: { input: port("fetch-p15", "output") },
  },
  {
    kind: "step",
    id: "sigma0-r18",
    type: "rotate-bits-right@1",
    params: { wordBits: 32, bits: 18 },
    portInputs: { input: port("fetch-p15", "output") },
  },
  {
    kind: "step",
    id: "sigma0-s3",
    type: "shift-bits-right@1",
    params: { wordBits: 32, bits: 3 },
    portInputs: { input: port("fetch-p15", "output") },
  },
  {
    kind: "step",
    id: "sigma0",
    type: "xor@1",
    params: { inputCount: 3 },
    portInputs: {
      operand0: port("sigma0-r7", "output"),
      operand1: port("sigma0-r18", "output"),
      operand2: port("sigma0-s3", "output"),
    },
  },
  // ── W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16} (mod 2^32) ──
  {
    kind: "step",
    id: "w-t",
    type: "add-mod-32@1",
    params: { inputCount: 4 },
    portInputs: {
      operand0: port("sigma1", "output"),
      operand1: port("fetch-p7", "output"),
      operand2: port("sigma0", "output"),
      operand3: port("fetch-p16", "output"),
    },
  },
  // ── FES body exit: 4-byte bytes-shape state ────────────────────────
  {
    kind: "step",
    id: "schedule-out",
    type: "bytes-to-state@1",
    params: {},
    portInputs: { input: port("w-t", "output") },
  },
];

// ─── Compression round body: 28 leaves per round ──────────────────────────
//
// Implements one round of SHA-256 compression per FIPS 180-4 §6.2.2.
// Reads state (32-byte working_vars a..h), reads W_t and K_t from aux,
// produces new state (the shifted working_vars new_a, a, b, c, new_e,
// e, f, g — renames-as-shift-down).

const buildCompressionRound = (t: number): StepNode => {
  const p = `round.${t}`;
  // Inline port helper that prepends the round prefix to source nodes
  // for the duration of this round build. Keeps the spec readable.
  const r = (node: string, portName: string) => port(`${p}.${node}`, portName);
  return {
    kind: "group",
    id: p,
    label: `Round ${t}`,
    children: [
      // ── Extract a..h from state ────────────────────────────────────
      {
        kind: "step",
        id: `${p}.state-in`,
        type: "state-to-bytes@1",
        params: {},
      },
      {
        kind: "step",
        id: `${p}.split`,
        type: "split-bytes@1",
        // 8 working-variable words; output0..output7 carry a..h respectively.
        params: { widths: [4, 4, 4, 4, 4, 4, 4, 4] },
        portInputs: { input: r("state-in", "output") },
      },
      // ── Fetch K_t from aux["K"] ────────────────────────────────────
      {
        kind: "step",
        id: `${p}.fetch-K`,
        type: "aux-load-bytes@1",
        params: { auxName: "K", byteLength: 256 },
      },
      {
        kind: "step",
        id: `${p}.K_t`,
        type: "byte-slice@1",
        params: { sourceByteLength: 256, offset: 4 * t, length: 4 },
        portInputs: { input: r("fetch-K", "output") },
      },
      // ── Fetch W_t from aux["W"] ────────────────────────────────────
      {
        kind: "step",
        id: `${p}.fetch-W`,
        type: "aux-load-bytes@1",
        params: { auxName: "W", byteLength: 256 },
      },
      {
        kind: "step",
        id: `${p}.W_t`,
        type: "byte-slice@1",
        params: { sourceByteLength: 256, offset: 4 * t, length: 4 },
        portInputs: { input: r("fetch-W", "output") },
      },
      // ── Σ1(e) = ROTR^6(e) ⊕ ROTR^11(e) ⊕ ROTR^25(e) ────────────────
      {
        kind: "step",
        id: `${p}.Sigma1-r6`,
        type: "rotate-bits-right@1",
        params: { wordBits: 32, bits: 6 },
        portInputs: { input: r("split", "output4") }, // e
      },
      {
        kind: "step",
        id: `${p}.Sigma1-r11`,
        type: "rotate-bits-right@1",
        params: { wordBits: 32, bits: 11 },
        portInputs: { input: r("split", "output4") },
      },
      {
        kind: "step",
        id: `${p}.Sigma1-r25`,
        type: "rotate-bits-right@1",
        params: { wordBits: 32, bits: 25 },
        portInputs: { input: r("split", "output4") },
      },
      {
        kind: "step",
        id: `${p}.Sigma1`,
        type: "xor@1",
        params: { inputCount: 3 },
        portInputs: {
          operand0: r("Sigma1-r6", "output"),
          operand1: r("Sigma1-r11", "output"),
          operand2: r("Sigma1-r25", "output"),
        },
      },
      // ── Σ0(a) = ROTR^2(a) ⊕ ROTR^13(a) ⊕ ROTR^22(a) ────────────────
      {
        kind: "step",
        id: `${p}.Sigma0-r2`,
        type: "rotate-bits-right@1",
        params: { wordBits: 32, bits: 2 },
        portInputs: { input: r("split", "output0") }, // a
      },
      {
        kind: "step",
        id: `${p}.Sigma0-r13`,
        type: "rotate-bits-right@1",
        params: { wordBits: 32, bits: 13 },
        portInputs: { input: r("split", "output0") },
      },
      {
        kind: "step",
        id: `${p}.Sigma0-r22`,
        type: "rotate-bits-right@1",
        params: { wordBits: 32, bits: 22 },
        portInputs: { input: r("split", "output0") },
      },
      {
        kind: "step",
        id: `${p}.Sigma0`,
        type: "xor@1",
        params: { inputCount: 3 },
        portInputs: {
          operand0: r("Sigma0-r2", "output"),
          operand1: r("Sigma0-r13", "output"),
          operand2: r("Sigma0-r22", "output"),
        },
      },
      // ── Ch(e,f,g) = (e ∧ f) ⊕ (¬e ∧ g) ─────────────────────────────
      {
        kind: "step",
        id: `${p}.Ch-not_e`,
        type: "not@1",
        params: {},
        portInputs: { input: r("split", "output4") }, // e
      },
      {
        kind: "step",
        id: `${p}.Ch-e_and_f`,
        type: "and@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("split", "output4"), // e
          operand1: r("split", "output5"), // f
        },
      },
      {
        kind: "step",
        id: `${p}.Ch-note_and_g`,
        type: "and@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("Ch-not_e", "output"),
          operand1: r("split", "output6"), // g
        },
      },
      {
        kind: "step",
        id: `${p}.Ch`,
        type: "xor@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("Ch-e_and_f", "output"),
          operand1: r("Ch-note_and_g", "output"),
        },
      },
      // ── Maj(a,b,c) = (a ∧ b) ⊕ (a ∧ c) ⊕ (b ∧ c) ───────────────────
      {
        kind: "step",
        id: `${p}.Maj-ab`,
        type: "and@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("split", "output0"), // a
          operand1: r("split", "output1"), // b
        },
      },
      {
        kind: "step",
        id: `${p}.Maj-ac`,
        type: "and@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("split", "output0"), // a
          operand1: r("split", "output2"), // c
        },
      },
      {
        kind: "step",
        id: `${p}.Maj-bc`,
        type: "and@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("split", "output1"), // b
          operand1: r("split", "output2"), // c
        },
      },
      {
        kind: "step",
        id: `${p}.Maj`,
        type: "xor@1",
        params: { inputCount: 3 },
        portInputs: {
          operand0: r("Maj-ab", "output"),
          operand1: r("Maj-ac", "output"),
          operand2: r("Maj-bc", "output"),
        },
      },
      // ── T1 = h + Σ1(e) + Ch(e,f,g) + K_t + W_t (5-way add) ─────────
      {
        kind: "step",
        id: `${p}.T1`,
        type: "add-mod-32@1",
        params: { inputCount: 5 },
        portInputs: {
          operand0: r("split", "output7"), // h
          operand1: r("Sigma1", "output"),
          operand2: r("Ch", "output"),
          operand3: r("K_t", "output"),
          operand4: r("W_t", "output"),
        },
      },
      // ── T2 = Σ0(a) + Maj(a,b,c) (2-way add) ────────────────────────
      {
        kind: "step",
        id: `${p}.T2`,
        type: "add-mod-32@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("Sigma0", "output"),
          operand1: r("Maj", "output"),
        },
      },
      // ── new_a = T1 + T2, new_e = d + T1 ────────────────────────────
      {
        kind: "step",
        id: `${p}.new_a`,
        type: "add-mod-32@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("T1", "output"),
          operand1: r("T2", "output"),
        },
      },
      {
        kind: "step",
        id: `${p}.new_e`,
        type: "add-mod-32@1",
        params: { inputCount: 2 },
        portInputs: {
          operand0: r("split", "output3"), // d
          operand1: r("T1", "output"),
        },
      },
      // ── Repack working vars: shift down by one slot. Next round's a..h:
      //    (new_a, a, b, c, new_e, e, f, g). The previous h falls off.
      {
        kind: "step",
        id: `${p}.repack`,
        type: "concat@1",
        params: { inputCount: 8 },
        portInputs: {
          input0: r("new_a", "output"),
          input1: r("split", "output0"), // a (shifted into b's slot)
          input2: r("split", "output1"), // b → c
          input3: r("split", "output2"), // c → d
          input4: r("new_e", "output"),
          input5: r("split", "output4"), // e → f
          input6: r("split", "output5"), // f → g
          input7: r("split", "output6"), // g → h
        },
      },
      {
        kind: "step",
        id: `${p}.state-out`,
        type: "bytes-to-state@1",
        params: {},
        portInputs: { input: r("repack", "output") },
      },
    ],
  };
};

// ─── Final-add: 13 leaves ──────────────────────────────────────────────────
//
// hash_i = working_vars[i] + H_i for i in 0..7 (mod 2^32). Per FIPS 180-4
// §6.2.2 step 4. The output is 32 bytes = the SHA-256 digest.

const buildFinalAddSteps = (): readonly StepNode[] => [
  {
    kind: "step",
    id: "final.state-in",
    type: "state-to-bytes@1",
    params: {},
  },
  {
    kind: "step",
    id: "final.split-wv",
    type: "split-bytes@1",
    params: { widths: [4, 4, 4, 4, 4, 4, 4, 4] },
    portInputs: { input: port("final.state-in", "output") },
  },
  {
    kind: "step",
    id: "final.fetch-H",
    type: "aux-load-bytes@1",
    params: { auxName: "H", byteLength: 32 },
  },
  {
    kind: "step",
    id: "final.split-H",
    type: "split-bytes@1",
    params: { widths: [4, 4, 4, 4, 4, 4, 4, 4] },
    portInputs: { input: port("final.fetch-H", "output") },
  },
  // 8 × 2-way add-mod-32: s_i = wv_i + H_i
  ...Array.from(
    { length: 8 },
    (_, i): StepNode => ({
      kind: "step",
      id: `final.s${i}`,
      type: "add-mod-32@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: port("final.split-wv", `output${i}`),
        operand1: port("final.split-H", `output${i}`),
      },
    }),
  ),
  // Reassemble the 8 sums into a 32-byte hash.
  {
    kind: "step",
    id: "final.assemble",
    type: "concat@1",
    params: { inputCount: 8 },
    portInputs: Object.fromEntries(
      Array.from({ length: 8 }, (_, i) => [`input${i}`, port(`final.s${i}`, "output")]),
    ),
  },
  {
    kind: "step",
    id: "final.out",
    type: "bytes-to-state@1",
    params: {},
    portInputs: { input: port("final.assemble", "output") },
  },
];

// ─── Spec builder ──────────────────────────────────────────────────────────

/**
 * Build the SHA-256 spec under the Slice 2.6d decomposed topology.
 *
 * Single-block only — supports messages whose total padded size is one
 * 64-byte block (i.e., message length ≤ 55 bytes per FIPS 180-4 §5.1.1
 * padding rules). Multi-block support lands in Slice 2.11.
 */
export const buildSha256Spec = (): CipherSpec => ({
  id: "sha-256@1",
  name: "SHA-256",
  stateShape: "bytes",
  // No key — hashes don't have keys. The `key` field is present but its
  // byteLength is 0; the UI's key editor will render an empty box.
  inputs: {
    plaintext: { shape: "bytes" },
    key: { byteLength: 0 },
  },
  steps: [
    // ─── Preprocessing ───────────────────────────────────────────────────
    // Plaintext entry bridge: expose initialState bytes on a port so
    // port-native primitives downstream can wire to them.
    {
      kind: "step",
      id: "plaintext-source",
      type: "state-to-bytes@1",
      params: {},
    },
    // Padding: input = plaintext, output = msg + 0x80 + zeros to ≡ 56 (mod 64).
    {
      kind: "step",
      id: "pad",
      type: "pad-with-byte@1",
      params: { padByte: 0x80, blockSize: 64, padTarget: 56 },
      portInputs: { input: port("plaintext-source", "output") },
    },
    // Length suffix: data = padded bytes, length-source = ORIGINAL message
    // (per FIPS 180-4 §5.1.1, the suffix encodes the original message's
    // bit-length, not the padded length).
    {
      kind: "step",
      id: "length-append",
      type: "append-be64-length@1",
      params: {},
      portInputs: {
        data: port("pad", "output"),
        "length-source": port("plaintext-source", "output"),
      },
    },
    // ─── Bridge: padded block (64 bytes) → state ─────────────────────────
    // Required so the FES-with-history can seed its history from
    // parent-scope state.bytes.
    {
      kind: "step",
      id: "seed-schedule",
      type: "bytes-to-state@1",
      params: {},
      portInputs: { input: port("length-append", "output") },
    },
    // ─── Message schedule (48 iterations, lookbackOffsets [2,7,15,16]) ────
    // 14-leaf decomposed body per iteration. After this, state = W[0..63]
    // (256 bytes — FES exit concatenates the full history).
    {
      kind: "for-each-subgraph-with-history",
      id: "msg-schedule",
      label: "Message schedule W_0..W_63",
      iterationCount: 48,
      lookbackOffsets: [2, 7, 15, 16],
      historyEntryByteLength: 4,
      children: buildScheduleBody(),
    },
    // ─── Q1 = (b): Publish W into aux["W"] ───────────────────────────────
    // State is the 256-byte W after the schedule exit. State-to-aux clones
    // it into aux["W"], where each compression round will read it from
    // (via aux-load-bytes + byte-slice). After this leaf, state is still
    // W (state-to-aux is identity on state); the next bridge below
    // overwrites state with the initial working variables.
    {
      kind: "step",
      id: "W-publish",
      type: "generic.state-to-aux-bytes@1",
      params: { auxName: "W" },
    },
    // ─── Load K into aux for the compression rounds ──────────────────────
    {
      kind: "step",
      id: "K-to-aux",
      type: "generic.aux-load@1",
      params: { auxName: "K", value: SHA256_K_BYTES },
    },
    // ─── Load H into aux for the final-add step ──────────────────────────
    {
      kind: "step",
      id: "H-to-aux",
      type: "generic.aux-load@1",
      params: { auxName: "H", value: SHA256_H_BYTES },
    },
    // ─── Initialize working variables from H_0..H_7 ──────────────────────
    // Emit H as a constant on a port, then bridge into state. After this,
    // state = working_vars (32 bytes) and compression rounds can begin.
    {
      kind: "step",
      id: "H-constant",
      type: "constant-load@1",
      params: { bytes: SHA256_H_BYTES },
    },
    {
      kind: "step",
      id: "init-working-vars",
      type: "bytes-to-state@1",
      params: {},
      portInputs: { input: port("H-constant", "output") },
    },
    // ─── 64 compression rounds (decomposed) ──────────────────────────────
    ...Array.from({ length: 64 }, (_, t) => buildCompressionRound(t)),
    // ─── Final add (decomposed): state (32 bytes wv) + aux["H"] → 32-byte hash
    ...buildFinalAddSteps(),
  ],
});

// ─── Public re-exports (consumers and tests) ──────────────────────────────

export const SHA256_INITIAL_HASH_VALUES = SHA256_H_WORDS;
export const SHA256_ROUND_CONSTANTS = SHA256_K_WORDS;
