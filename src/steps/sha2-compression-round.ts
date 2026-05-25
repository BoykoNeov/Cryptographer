/**
 * sha2.compression-round — one round of the SHA-256 compression function
 * (universal-port plan Phase 2 Slice 2.6b, 2026-05-25).
 *
 * **Where it sits.** The SHA-256 spec hand-rolls 64 leaves of this type,
 * one per round t ∈ [0, 64) (per Option A — hand-rolled round groups, user
 * pick 2026-05-25). Each round group wraps one leaf of this step type
 * with `params.roundIndex = t` set to the round index.
 *
 * **State layout: 288 bytes = working-vars (32) || W (256).** During
 * compression, the runtime `state` is a 288-byte BytesState. The first
 * 32 bytes carry the eight 32-bit working variables a..h (in big-endian
 * concatenation order); the remaining 256 bytes carry the full message
 * schedule W_0..W_63 (precomputed by the FES-with-history before
 * compression starts). This layout was chosen at re-scope time (Slice
 * 2.6b, 2026-05-25) so each round leaf can read state once and have
 * access to BOTH the current working variables AND the per-round W_t
 * lookup, without needing a snapshot-to-aux primitive.
 *
 * **K_t source.** The round constants K_0..K_63 are loaded into aux["K"]
 * once at the start of the cipher via `generic.aux-load@1` (params.value
 * = the 256-byte K table). Each compression round reads K_t = aux["K"]
 * slice [4t, 4t+4]. K is a constant table (FIPS 180-4 §4.2.2), so this
 * single load suffices.
 *
 * **Math (FIPS 180-4 §6.2.2 step 3, per round t):**
 *
 * ```
 * T1 = h + Σ1(e) + Ch(e, f, g) + K_t + W_t   (mod 2^32)
 * T2 = Σ0(a) + Maj(a, b, c)                  (mod 2^32)
 * h = g
 * g = f
 * f = e
 * e = (d + T1)            (mod 2^32)
 * d = c
 * c = b
 * b = a
 * a = (T1 + T2)           (mod 2^32)
 *
 * Σ0(x) = ROTR²(x)  ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
 * Σ1(x) = ROTR⁶(x)  ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
 * Ch(x,y,z)  = (x ∧ y) ⊕ (¬x ∧ z)
 * Maj(x,y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
 * ```
 *
 * **Why a single SHA-256-specific helper instead of a port-native
 * composition** (Slice 2.6b re-scope, 2026-05-25). Same rationale as
 * `sha2.message-schedule-step@1` — port-native decomposition requires
 * bridge primitives (slice-by-offset, multi-output container, cross-scope
 * wiring) that aren't yet designed. Slice 2.6d will replace this helper
 * with the decomposed form. Math is byte-identical to FIPS — pinned by
 * the Slice 2.3 helpers test + this file's KAT runs.
 *
 * **Pedagogy preserved via narration.** Spec authors should attach a
 * `narrationOverride` to each per-round leaf describing the round's
 * specific behavior (which T1 / T2 / Σ0 / Σ1 path was taken with what
 * intermediate values); the inspector renders that for an
 * "expanded view" experience even though the chip stays atomic.
 *
 * **Sign-extension discipline.** Same as `add-mod-32@1` and
 * `sha2.message-schedule-step@1` — every modular-add intermediate gets
 * `>>> 0` to stay in the unsigned 32-bit domain.
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
import { decodeBE32, encodeBE32, ror32 } from "../core/word-codec";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly roundIndex: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("sha2.compression-round: params must be an object");
  }
  const p = params as Record<string, Json>;
  const roundIndex = p.roundIndex;
  if (
    typeof roundIndex !== "number" ||
    !Number.isInteger(roundIndex) ||
    roundIndex < 0 ||
    roundIndex > 63
  ) {
    throw new Error(
      `sha2.compression-round: params.roundIndex must be an integer in [0, 63]; got ${String(roundIndex)}`,
    );
  }
  return { roundIndex };
};

// ─── SHA-256 helper functions (Σ0/Σ1/Ch/Maj per FIPS 180-4 §4.1.2) ────────

const Sigma0 = (x: number): number => (ror32(x, 2) ^ ror32(x, 13) ^ ror32(x, 22)) >>> 0;
const Sigma1 = (x: number): number => (ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25)) >>> 0;
const Ch = (x: number, y: number, z: number): number => ((x & y) ^ (~x & z)) >>> 0;
const Maj = (x: number, y: number, z: number): number => ((x & y) ^ (x & z) ^ (y & z)) >>> 0;

// ─── Executor ─────────────────────────────────────────────────────────────

export const sha2CompressionRound: StepExecutor = (state, params, ctx) => {
  const { roundIndex } = readParams(params);

  if (state.shape !== "bytes") {
    throw new Error(
      `sha2.compression-round: state.shape must be "bytes" (got "${state.shape}"); compression state layout is 288-byte BytesState`,
    );
  }
  if (state.bytes.length !== 288) {
    throw new Error(
      `sha2.compression-round: state.bytes.length must be 288 (32 bytes working-vars + 256 bytes W); got ${state.bytes.length}`,
    );
  }

  // K table — full 256 bytes of round constants, slice 4t..4t+4 for K_t.
  const kAux = ctx.aux.get("K");
  if (!(kAux instanceof Uint8Array)) {
    throw new Error(
      "sha2.compression-round: aux['K'] must be a Uint8Array containing the 256-byte K_0..K_63 table (load via aux-load before compression)",
    );
  }
  if (kAux.length !== 256) {
    throw new Error(
      `sha2.compression-round: aux['K'].length must be 256 (64 × 4-byte words); got ${kAux.length}`,
    );
  }

  // Decode working variables a..h from state[0..32] as 8 BE32 words.
  // Order: bytes[0..4] = a, [4..8] = b, ..., [28..32] = h.
  const a = decodeBE32(state.bytes, 0);
  const b = decodeBE32(state.bytes, 4);
  const c = decodeBE32(state.bytes, 8);
  const d = decodeBE32(state.bytes, 12);
  const e = decodeBE32(state.bytes, 16);
  const f = decodeBE32(state.bytes, 20);
  const g = decodeBE32(state.bytes, 24);
  const h = decodeBE32(state.bytes, 28);

  // W_t: slice 4 bytes at offset 32 + 4*roundIndex within state.
  const wOffset = 32 + 4 * roundIndex;
  const wT = decodeBE32(state.bytes, wOffset);

  // K_t: slice 4 bytes at offset 4*roundIndex within aux['K'].
  const kT = decodeBE32(kAux, 4 * roundIndex);

  // T1 = h + Σ1(e) + Ch(e,f,g) + K_t + W_t (mod 2^32).
  // Pairwise `>>> 0` after each add to stay unsigned in JS's signed-int
  // bitwise semantics (see add-mod-32@1 for the same discipline).
  const t1 = (((h + Sigma1(e)) >>> 0) + ((Ch(e, f, g) + ((kT + wT) >>> 0)) >>> 0)) >>> 0;

  // T2 = Σ0(a) + Maj(a,b,c) (mod 2^32).
  const t2 = (Sigma0(a) + Maj(a, b, c)) >>> 0;

  // Shuffle working variables. The "let-style" assignment order
  // (h=g, g=f, ..., b=a) is from FIPS 180-4 §6.2.2; we just compute the
  // new values directly without aliasing.
  const newA = (t1 + t2) >>> 0;
  const newB = a;
  const newC = b;
  const newD = c;
  const newE = (d + t1) >>> 0;
  const newF = e;
  const newG = f;
  const newH = g;

  // Compose new state: working-vars (32 bytes new) || W (256 bytes
  // unchanged — copy verbatim from the input state).
  const out = new Uint8Array(288);
  encodeBE32(out, 0, newA);
  encodeBE32(out, 4, newB);
  encodeBE32(out, 8, newC);
  encodeBE32(out, 12, newD);
  encodeBE32(out, 16, newE);
  encodeBE32(out, 20, newF);
  encodeBE32(out, 24, newG);
  encodeBE32(out, 28, newH);
  // W block: copy bytes[32..288] from input.
  out.set(state.bytes.subarray(32), 32);

  const next: BytesState = { shape: "bytes", bytes: out };
  return { state: next, auxReads: ["K"] };
};

// ─── Documentation ────────────────────────────────────────────────────────

export const sha2CompressionRoundDoc: StepDocumentation = {
  name: "SHA-256 Compression Round",
  summary:
    "One round of SHA-256's compression function. Updates eight working variables in place, reading the round constant K_t and message-schedule word W_t.",
  detail: `# SHA-256 Compression Round

Executes one round t ∈ [0, 64) of SHA-256's compression function per
FIPS 180-4 §6.2.2 step 3. Reads the round's K_t (from aux['K']) and W_t
(from state[32 + 4t..]), updates the eight working variables a..h, and
writes back a new 288-byte state.

## State layout (288 bytes)

\`\`\`
state[0..32]     = a || b || c || d || e || f || g || h  (working vars,
                                                          32-bit BE each)
state[32..288]   = W_0 || W_1 || ... || W_63             (message schedule,
                                                          32-bit BE each)
\`\`\`

## Math

\`\`\`
T1 = h + Σ1(e) + Ch(e,f,g) + K_t + W_t   (mod 2^32)
T2 = Σ0(a) + Maj(a,b,c)                   (mod 2^32)

(new h, g, f, e) = (g, f, e, (d + T1) mod 2^32)
(new d, c, b, a) = (c, b, a, (T1 + T2) mod 2^32)

Σ0(x) = ROTR²(x)  ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
Σ1(x) = ROTR⁶(x)  ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
Ch(x,y,z)  = (x ∧ y) ⊕ (¬x ∧ z)
Maj(x,y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
\`\`\`

## Where it fits

The SHA-256 spec hand-rolls 64 leaves of this type (one per round t),
wrapped in 64 sibling round groups at the spec root. Compression runs
sequentially as a state-thread (no \`for-each-subgraph\`) because each
round's state is the previous round's state. After all 64 rounds,
\`sha2.final-add@1\` produces the 32-byte hash.

## Why a SHA-256-specific helper

Slice 2.6b re-scope (2026-05-25): expressing each round as a port-native
composition of rotate/xor/and/not/add primitives requires bridge
primitives (slice-by-offset, cross-scope wiring) that aren't yet designed.
Slice 2.6d will decompose. Math is identical — pinned by the Slice 2.3
helpers test + this file's KATs.

## Errors

- Throws if \`params.roundIndex\` is missing or out of [0, 63].
- Throws if state is not 288-byte BytesState.
- Throws if \`aux['K']\` is missing or not 256 bytes.

## Phase status

Shipped in Slice 2.6b of the universal-port-dataflow plan. Subject to
decomposition into port-native primitives in Slice 2.6d.`,
  params: new Map([
    [
      "roundIndex",
      "Round index t in [0, 63]. Selects W_t from state[32 + 4t..] and K_t from aux['K'][4t..].",
    ],
  ]),
  references: [
    "FIPS 180-4 §6.2.2 step 3 (SHA-256 compression function round structure)",
    "FIPS 180-4 §4.1.2 (Σ0, Σ1, Ch, Maj helper definitions)",
    "FIPS 180-4 §4.2.2 (K_0..K_63 round constants)",
    "docs/plans/universal-port-phase-2-slices.md (Slice 2.6b)",
  ],
  shapeContract: { input: "bytes", output: "bytes" },
};

// ─── Universal port-dataflow metadata ─────────────────────────────────────
// Lifted-legacy: state byteLength=288, aux read of "K" (256 bytes).
// stateLayout: "bytes" — the runtime uses `stateToPortBytes(state, "bytes")`
// to project, and the executor sees state as a 288-byte BytesState.

export const sha2CompressionRoundMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
  auxReadPorts: (_params: Json): ReadonlyMap<string, string> => new Map([["K", "K"]]),
};

export const sha2CompressionRoundPortContract: PortContract = {
  inputs: new Map<string, PortShape>([
    ["state", { byteLength: 288, layout: "raw" }],
    ["K", { byteLength: 256, layout: "raw" }],
  ]),
  outputs: new Map<string, PortShape>([["state", { byteLength: 288, layout: "raw" }]]),
};
