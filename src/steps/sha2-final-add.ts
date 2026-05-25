/**
 * sha2.final-add — SHA-256 final-add step (universal-port plan Phase 2
 * Slice 2.6b, 2026-05-25).
 *
 * After 64 compression rounds, state.bytes is 288 bytes:
 *   - bytes[0..32]   = final working variables a..h (eight 32-bit BE words)
 *   - bytes[32..288] = W (256 bytes, untouched throughout compression)
 *
 * The cipher's final step per FIPS 180-4 §6.2.2 step 4 is to add the
 * initial hash values H_0..H_7 to the final a..h (modulo 2^32, per word),
 * producing the 32-byte hash output. This step:
 *
 *   1. Reads `state` (288 bytes — the post-compression layout)
 *   2. Reads `aux["H"]` (32 bytes — the initial H_0..H_7 concat,
 *      loaded once via aux-load at the start of the cipher)
 *   3. Computes hash[i*4..(i+1)*4] = state[i*4..(i+1)*4] + H_i (mod 2^32)
 *      for i ∈ [0, 8)
 *   4. Returns a 32-byte BytesState as the final hash
 *
 * The state shrinks from 288 to 32 bytes — the W tail is discarded as
 * we exit the per-message-block boundary. For single-block messages
 * ("abc" in 2.6b's KAT) this is the cipher's final state.
 *
 * **Why a SHA-256-specific helper** (Slice 2.6b re-scope, 2026-05-25).
 * Same posture as `sha2.message-schedule-step@1` and
 * `sha2.compression-round@1` — port-native composition would require
 * slice-by-offset and concat primitives (the latter exists at this slice,
 * but the slice-by-offset primitive doesn't, and pulling state from 288
 * bytes down to 32 bytes is awkward without it). Slice 2.6d will
 * decompose. Math is byte-identical — pinned by KATs in this file's
 * test suite.
 */

import type {
  BytesState,
  Json,
  PortContract,
  PortShape,
  ProjectionMetadata,
  StepDocumentation,
  StepExecutor,
} from "../core/types";
import { decodeBE32, encodeBE32 } from "../core/word-codec";

// ─── Params ───────────────────────────────────────────────────────────────
// No params. The H source is fixed at aux["H"] by convention (the spec
// loads it via aux-load at startup). If a future hash variant needs a
// different aux key, parametrize then.

const readParams = (params: Json): void => {
  if (params === null || typeof params !== "object" || Array.isArray(params)) {
    throw new Error("sha2.final-add: params must be an object (use {} for default)");
  }
};

// ─── Executor ─────────────────────────────────────────────────────────────

export const sha2FinalAdd: StepExecutor = (state, params, ctx) => {
  readParams(params);

  if (state.shape !== "bytes") {
    throw new Error(
      `sha2.final-add: state.shape must be "bytes" (got "${state.shape}"); compression state layout is 288-byte BytesState`,
    );
  }
  if (state.bytes.length !== 288) {
    throw new Error(
      `sha2.final-add: state.bytes.length must be 288 (32 working-vars + 256 W); got ${state.bytes.length}`,
    );
  }

  const hAux = ctx.aux.get("H");
  if (!(hAux instanceof Uint8Array)) {
    throw new Error(
      "sha2.final-add: aux['H'] must be a Uint8Array containing the 32-byte H_0..H_7 concat (load via aux-load at cipher start)",
    );
  }
  if (hAux.length !== 32) {
    throw new Error(
      `sha2.final-add: aux['H'].length must be 32 (8 × 4-byte H_i words); got ${hAux.length}`,
    );
  }

  // hash[i] = (state_workingVar_i + H_i) mod 2^32 for i ∈ [0, 8).
  // Working vars are at state.bytes[0..32]; H is at aux['H'][0..32].
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const aHash = decodeBE32(state.bytes, 4 * i);
    const hValue = decodeBE32(hAux, 4 * i);
    const sum = (aHash + hValue) >>> 0;
    encodeBE32(out, 4 * i, sum);
  }

  const next: BytesState = { shape: "bytes", bytes: out };
  return { state: next, auxReads: ["H"] };
};

// ─── Documentation ────────────────────────────────────────────────────────

export const sha2FinalAddDoc: StepDocumentation = {
  name: "SHA-256 Final Add",
  summary:
    "Add the initial hash values H_0..H_7 to the final working variables a..h (mod 2^32, per word), producing the 32-byte SHA-256 digest.",
  detail: `# SHA-256 Final Add

The cipher's final step per FIPS 180-4 §6.2.2 step 4. After 64 compression
rounds, the working variables a..h hold an intermediate value; this step
adds the initial hash values H_0..H_7 to them (modulo 2^32, per word) to
produce the 32-byte digest:

\`\`\`
hash_word_i = (working_var_i + H_i) mod 2^32   for i ∈ [0, 8)
hash       = hash_word_0 || hash_word_1 || ... || hash_word_7
\`\`\`

## State shape transformation

The state shrinks from 288 to 32 bytes. The W block (state[32..288]),
preserved through all 64 compression rounds, is discarded — it has no
further use after the per-block hash is computed. For single-block
messages this 32-byte state IS the cipher's final state.

## Where it fits

The last leaf of the SHA-256 spec, after the 64 compression-round
groups. Reads aux["H"] (the H_0..H_7 concat, loaded via aux-load at the
start of the cipher and preserved unchanged through compression).

## Why a SHA-256-specific helper

Slice 2.6b re-scope (2026-05-25): the cleanest port-native decomposition
would be (a) state-to-bytes (288) → slice-by-offset(0, 32) → 8-way
unconcatenated 4-byte slices, (b) eight 2-way add-mod-32 leaves (each
adds H_i to vars_i), (c) 8-way concat → bytes-to-state. But slice-by-
offset doesn't exist yet, and the assembly is 25+ leaves for what is
algebraically 8 add-mod-32 operations on a known 32-byte buffer.

Slice 2.6d will decompose once slice-by-offset is designed.

## Errors

- Throws if state is not 288-byte BytesState.
- Throws if aux["H"] is missing or not 32 bytes.

## Phase status

Shipped in Slice 2.6b of the universal-port-dataflow plan. Subject to
decomposition into port-native primitives in Slice 2.6d.`,
  params: new Map([["(no params)", "This step takes no parameters; pass `{}`."]]),
  references: [
    "FIPS 180-4 §6.2.2 step 4 (SHA-256 final-add for per-block digest)",
    "FIPS 180-4 §5.3.3 (H_0..H_7 initial hash values)",
    "docs/plans/universal-port-phase-2-slices.md (Slice 2.6b)",
  ],
  shapeContract: { input: "bytes", output: "bytes" },
};

// ─── Universal port-dataflow metadata ─────────────────────────────────────
// Lifted-legacy: state byteLength asymmetric (288 in, 32 out — SHA-256's
// per-block-exit boundary). stateLayout: "bytes". One aux read of "H"
// (32 bytes).

export const sha2FinalAddMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state-in",
  stateOutputPort: "state-out",
  auxReadPorts: (_params: Json): ReadonlyMap<string, string> => new Map([["H", "H"]]),
};

/**
 * Asymmetric state port byteLengths — `state-in` is 288 bytes, `state-out`
 * is 32 bytes. Distinct port names so the contract is honest about the
 * shape transformation.
 */
export const sha2FinalAddPortContract: PortContract = {
  inputs: new Map<string, PortShape>([
    ["state-in", { byteLength: 288, layout: "raw" }],
    ["H", { byteLength: 32, layout: "raw" }],
  ]),
  outputs: new Map<string, PortShape>([["state-out", { byteLength: 32, layout: "raw" }]]),
};
