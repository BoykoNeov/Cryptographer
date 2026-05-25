/**
 * SHA-256 cipher spec — first port-native cipher under the universal-port
 * dataflow plan (Phase 2 Slice 2.6b, 2026-05-25).
 *
 * **Topology overview** (Option A — hand-rolled 64 round groups, user
 * pick 2026-05-25):
 *
 * ```
 * 1.  state-to-bytes "plaintext-source"   → output = plaintext bytes
 * 2.  pad-with-byte "pad"                  → output = padded bytes (msg + 0x80 + zeros to ≡ 56 mod 64)
 * 3.  append-be64-length "length-append"   → output = 64-byte padded block (single-block "abc")
 * 4.  bytes-to-state "seed-schedule"       → state = padded block (64 bytes)
 * 5.  for-each-subgraph-with-history       → state = W[0..63] (256 bytes)
 *       body: sha2.message-schedule-step@1
 *       iterationCount=48, lookbackOffsets=[2,7,15,16], entryLen=4
 * 6.  generic.aux-load "H-to-aux"          → aux["H"] = H_0..H_7 (32 bytes)
 * 7.  generic.aux-load "K-to-aux"          → aux["K"] = K_0..K_63 (256 bytes)
 * 8.  state-to-bytes "W-source"            → output = W bytes (state at this point)
 * 9.  constant-load "H-constant"           → output = H_0..H_7 (32 bytes)
 * 10. concat "compression-state-init"      → output = H || W (288 bytes)
 * 11. bytes-to-state "compression-bridge"  → state = 288 bytes
 * 12. 64 × group {sha2.compression-round@1}, each round t with params.roundIndex=t
 *     After all rounds: state = (final a..h, 32 bytes) || W (256 bytes)
 * 13. sha2.final-add "final-add"           → state = final hash (32 bytes)
 * ```
 *
 * **Single-block scope.** This spec assumes the message fits in ONE
 * 64-byte block (after padding + length-suffix). The "abc" KAT (FIPS
 * 180-4 §A.1) is the canonical reference for single-block. Multi-block
 * support (per-block outer loop, running hash threaded across blocks)
 * is deferred to Slice 2.11's KAT matrix per the Slice 2.6b re-scope.
 *
 * **What ships here vs what's planned**:
 *   - SHIPS now (Slice 2.6b): coarse-granularity helpers
 *     (sha2.message-schedule-step, sha2.compression-round, sha2.final-add).
 *     Each is a lifted-legacy step with internal math byte-identical to
 *     FIPS 180-4. The cipher is visible in the UI; the KAT passes.
 *   - PLANNED Slice 2.6c: design the bridge vocabulary (slice-by-offset,
 *     aux-to-bytes, cross-scope wiring) needed to express the helpers as
 *     port-native compositions.
 *   - PLANNED Slice 2.6d: replace the helpers with in-spec compositions
 *     (rotate-bits-right + shift-bits-right + xor + add-mod-32 + and + not
 *     chains for σ0/σ1/Σ0/Σ1/Ch/Maj/T1/T2). Math is byte-identical to
 *     this slice — pinned by Slice 2.3/2.5 helper tests.
 *
 * **Pedagogy.** Each spec leaf can carry a `narrationOverride` describing
 * its purpose ("Round 5: T1 = h + Σ1(e) + Ch(e,f,g) + K_5 + W_5"); this
 * surfaces the math via the inspector even though the chips are atomic
 * in this slice. Cipher-specific narration is deferred to a polish slice
 * — for 2.6b's first ship, default doc strings carry the explanations.
 *
 * **References:**
 *   - FIPS 180-4 §5.1.1 — Preprocessing (padding + length suffix)
 *   - FIPS 180-4 §5.3.3 — Initial hash values H_0..H_7
 *   - FIPS 180-4 §4.2.2 — Round constants K_0..K_63
 *   - FIPS 180-4 §6.2.2 — Single-block message hash computation
 *   - FIPS 180-4 §A.1   — KAT for the 3-byte message "abc"
 *   - docs/plans/universal-port-phase-2-slices.md (Slice 2.6b — re-scope)
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
 * (constant-load → concat with W → bytes-to-state), (2) as the per-word
 * addend in the final-add step (aux["H"]).
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

// ─── Spec builders ────────────────────────────────────────────────────────

/**
 * Build the 64 compression round groups. Each round is a `group` with a
 * single `sha2.compression-round@1` leaf carrying `params.roundIndex = t`.
 * Wrapping each round in its own group makes the graph view collapsible
 * per-round AND lets future slices attach per-round `narrationOverride`
 * docs without restructuring the spec.
 *
 * Each round inherits the previous round's state via the implicit state-
 * thread fallback (state-thread is preserved for lifted-legacy steps —
 * each `sha2.compression-round@1` reads state and writes new state).
 */
const buildCompressionRoundGroups = (): readonly StepNode[] => {
  const rounds: StepNode[] = [];
  for (let t = 0; t < 64; t++) {
    rounds.push({
      kind: "group",
      id: `round.${t}`,
      label: `Round ${t}`,
      children: [
        {
          kind: "step",
          id: `compress.${t}`,
          type: "sha2.compression-round@1",
          params: { roundIndex: t },
        },
      ],
    });
  }
  return rounds;
};

/**
 * Build the SHA-256 spec.
 *
 * Single-block only — supports messages whose total padded size is one
 * 64-byte block (i.e., message length ≤ 55 bytes per FIPS 180-4 §5.1.1
 * padding rules). Multi-block support lands in Slice 2.11 (KAT matrix
 * adds an outer per-block FES with cross-block hash threading).
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
      portInputs: {
        input: { node: "plaintext-source", port: "output" },
      },
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
        data: { node: "pad", port: "output" },
        "length-source": { node: "plaintext-source", port: "output" },
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
      portInputs: {
        input: { node: "length-append", port: "output" },
      },
    },
    // ─── Message schedule (48 iterations, lookbackOffsets [2,7,15,16]) ────
    // After this, state = W[0..63] (256 bytes).
    {
      kind: "for-each-subgraph-with-history",
      id: "msg-schedule",
      label: "Message schedule W_0..W_63",
      iterationCount: 48,
      lookbackOffsets: [2, 7, 15, 16],
      historyEntryByteLength: 4,
      children: [
        {
          kind: "step",
          id: "expand",
          type: "sha2.message-schedule-step@1",
          params: {},
        },
      ],
    },
    // ─── Load H into aux for the final-add step ──────────────────────────
    // Uses generic.aux-load@1 (lifted-legacy). The value is the 32-byte
    // H_0..H_7 concatenation; final-add reads it as aux["H"].
    {
      kind: "step",
      id: "H-to-aux",
      type: "generic.aux-load@1",
      params: { auxName: "H", value: SHA256_H_BYTES },
    },
    // ─── Load K into aux for the compression rounds ──────────────────────
    {
      kind: "step",
      id: "K-to-aux",
      type: "generic.aux-load@1",
      params: { auxName: "K", value: SHA256_K_BYTES },
    },
    // ─── Build the 288-byte compression state (H || W) ───────────────────
    // Expose W (state.bytes, 256 bytes) on a port.
    {
      kind: "step",
      id: "W-source",
      type: "state-to-bytes@1",
      params: {},
    },
    // Emit H_0..H_7 as a constant on a port.
    {
      kind: "step",
      id: "H-constant",
      type: "constant-load@1",
      params: { bytes: SHA256_H_BYTES },
    },
    // Concat H || W → 288 bytes.
    {
      kind: "step",
      id: "compression-state-init",
      type: "concat@1",
      params: { inputCount: 2 },
      portInputs: {
        input0: { node: "H-constant", port: "output" },
        input1: { node: "W-source", port: "output" },
      },
    },
    // Bridge: 288-byte concat → state. State is now ready for compression.
    {
      kind: "step",
      id: "compression-bridge",
      type: "bytes-to-state@1",
      params: {},
      portInputs: {
        input: { node: "compression-state-init", port: "output" },
      },
    },
    // ─── 64 compression rounds ───────────────────────────────────────────
    ...buildCompressionRoundGroups(),
    // ─── Final add: state (288) → 32-byte hash ───────────────────────────
    // Reads aux["H"] (loaded earlier) and the post-compression working
    // variables (state[0..32]). Output state is the 32-byte SHA-256 digest.
    {
      kind: "step",
      id: "final-add",
      type: "sha2.final-add@1",
      params: {},
    },
  ],
});

// ─── Public re-exports (consumers and tests) ──────────────────────────────

export const SHA256_INITIAL_HASH_VALUES = SHA256_H_WORDS;
export const SHA256_ROUND_CONSTANTS = SHA256_K_WORDS;
