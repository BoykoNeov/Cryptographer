/**
 * sha2.message-schedule-step — single body leaf for SHA-256's message-
 * schedule expansion (universal-port plan Phase 2 Slice 2.6b, 2026-05-25).
 *
 * **Where it sits.** The body of a `for-each-subgraph-with-history` node
 * with `iterationCount: 48`, `lookbackOffsets: [2, 7, 15, 16]`,
 * `historyEntryByteLength: 4`. Per FIPS 180-4 §6.2.2 step 1:
 *
 * ```
 * W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}   (mod 2^32)
 *
 * σ0(x) = ROTR⁷(x)  ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
 * σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
 * ```
 *
 * The runtime's FES-with-history walker populates `aux["prior-N"]` for
 * each declared offset before each body iteration. This step reads those
 * four aux values (each 4 bytes, big-endian 32-bit word), computes W_t,
 * and emits a 4-byte BytesState as its output. The runtime's
 * FES-with-history then appends that to the history buffer.
 *
 * **Why a single SHA-256-specific helper instead of a port-native
 * composition** (Slice 2.6b re-scope discovery, 2026-05-25). Expressing
 * the W_t recurrence as a port-native chain of `rotate-bits-right` +
 * `shift-bits-right` + `xor` + `add-mod-32` leaves would require bridge
 * primitives that don't yet exist (aux-key → port input, plus per-leaf
 * state-update wiring inside FES-with-history bodies). Slice 2.6b re-
 * scoped to ship SHA-256 at coarser step granularity here; Slice 2.6c+d
 * plan and execute the in-spec decomposition once the bridge vocabulary
 * is designed. The math inside this executor is byte-identical to what
 * the future composition will produce — pinned at test scope in
 * `tests/sha256-message-schedule.test.ts` (Slice 2.5).
 *
 * **Pedagogy preserved via narration.** A future `narrationOverride` on
 * each spec leaf of this type can describe σ0 / σ1 internals at the
 * inspector level even though the chips aren't decomposed in the graph.
 *
 * **Sign-extension discipline.** JS `+` returns signed when the result
 * would set bit 31. The intermediate `>>> 0` coercions inside the
 * executor keep all arithmetic unsigned — same caveat as
 * `add-mod-32@1`'s Slice 2.1b executor and the Slice 2.5 emulation tests.
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
import { decodeBE32, encodeBE32, ror32, shr32 } from "../core/word-codec";

// ─── Params ───────────────────────────────────────────────────────────────
// No params today. The lookback offsets are fixed by FIPS 180-4 §6.2.2 —
// SHA-256 always reads at -2, -7, -15, -16. If a future hash function in
// this family uses a different recurrence shape, register a sibling step
// (e.g., `sha512.message-schedule-step@1` with 64-bit word math).

const readParams = (params: Json): void => {
  if (params === null || typeof params !== "object" || Array.isArray(params)) {
    throw new Error("sha2.message-schedule-step: params must be an object (use {} for default)");
  }
};

// ─── σ0 / σ1 helpers ──────────────────────────────────────────────────────
//
// FIPS 180-4 §4.1.2. Inline (not exported) because they're load-bearing
// for THIS step's executor only — the Slice 2.5 test file
// `sha256-message-schedule.test.ts` already pins the math byte-for-byte
// against hand-derived KATs and a TS oracle. If a future consumer (HMAC
// inner-hash, etc.) needs σ0/σ1, lift to `core/word-codec.ts` or a
// dedicated `core/sha256-helpers.ts`.

const sigma0 = (x: number): number => (ror32(x, 7) ^ ror32(x, 18) ^ shr32(x, 3)) >>> 0;
const sigma1 = (x: number): number => (ror32(x, 17) ^ ror32(x, 19) ^ shr32(x, 10)) >>> 0;

// ─── Legacy executor ──────────────────────────────────────────────────────
//
// Reads aux["prior-2"], aux["prior-7"], aux["prior-15"], aux["prior-16"]
// (4 bytes each), computes W_t, returns a 4-byte BytesState. Declares
// `auxReads` so the runtime records the per-iteration aux access in
// `frame.auxRead`.
//
// Missing-key strategy: throw. The FES-with-history runtime ALWAYS sets
// every declared lookbackOffset's aux key before each body walk — if one
// of these reads misses, something is structurally wrong (the spec's
// lookbackOffsets don't match this executor's expectations, or the runtime
// is buggy). Loud failure is more useful than silent passthrough here
// (unlike aux-copy/aux-xor's graceful behavior, which is designed for
// half-wired authoring states).

const REQUIRED_PRIORS = ["prior-2", "prior-7", "prior-15", "prior-16"] as const;

export const sha2MessageScheduleStep: StepExecutor = (_state, params, ctx) => {
  readParams(params);

  // Fetch and validate all four priors first. Loud failure on any
  // missing or wrong-shape prior — the body cannot proceed.
  const priors: Uint8Array[] = [];
  for (const key of REQUIRED_PRIORS) {
    const v = ctx.aux.get(key);
    if (!(v instanceof Uint8Array)) {
      throw new Error(
        `sha2.message-schedule-step: aux["${key}"] must be a Uint8Array (the FES-with-history runtime should have set this; check that lookbackOffsets includes 2, 7, 15, 16)`,
      );
    }
    if (v.length !== 4) {
      throw new Error(
        `sha2.message-schedule-step: aux["${key}"] must be 4 bytes (SHA-256 32-bit word); got ${v.length}`,
      );
    }
    priors.push(v);
  }

  // Decode each prior as a big-endian 32-bit unsigned word.
  const wPrev2 = decodeBE32(priors[0] as Uint8Array, 0);
  const wPrev7 = decodeBE32(priors[1] as Uint8Array, 0);
  const wPrev15 = decodeBE32(priors[2] as Uint8Array, 0);
  const wPrev16 = decodeBE32(priors[3] as Uint8Array, 0);

  // W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}  (mod 2^32).
  // Pairwise `>>> 0` to keep every intermediate sum unsigned in JS's
  // signed-int bitwise semantics. The final value is encoded back as a
  // big-endian 4-byte word.
  const sigma1Term = sigma1(wPrev2);
  const sigma0Term = sigma0(wPrev15);
  const wT = (((sigma1Term + wPrev7) >>> 0) + ((sigma0Term + wPrev16) >>> 0)) >>> 0;

  const outBytes = new Uint8Array(4);
  encodeBE32(outBytes, 0, wT);
  const next: BytesState = { shape: "bytes", bytes: outBytes };
  // Declared reads — the runtime stamps these into frame.auxRead.
  const auxReads: readonly string[] = [...REQUIRED_PRIORS];
  return { state: next, auxReads };
};

// ─── Documentation ────────────────────────────────────────────────────────

export const sha2MessageScheduleStepDoc: StepDocumentation = {
  name: "SHA-256 Message Schedule Step",
  summary:
    "Compute one new word W_t of the SHA-256 message schedule by combining four historical W values via σ0, σ1, and modular addition.",
  detail: `# SHA-256 Message Schedule Step

The per-iteration body of SHA-256's message-schedule expansion. Reads the
runtime-populated lookback aux values \`aux["prior-2"]\`, \`aux["prior-7"]\`,
\`aux["prior-15"]\`, \`aux["prior-16"]\` (each 4 bytes, big-endian 32-bit
word), computes the next message-schedule word \`W_t\` per FIPS 180-4
§6.2.2 step 1, and writes it as a 4-byte BytesState.

## Math

\`\`\`
W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}   (mod 2^32)

σ0(x) = ROTR⁷(x)  ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
\`\`\`

## Where it fits

Inside the SHA-256 spec's message-schedule \`for-each-subgraph-with-history\`
node, configured with:

\`\`\`json
{
  "kind": "for-each-subgraph-with-history",
  "id": "msg-schedule",
  "iterationCount": 48,
  "lookbackOffsets": [2, 7, 15, 16],
  "historyEntryByteLength": 4,
  "children": [
    {
      "kind": "step",
      "id": "msg-schedule-step",
      "type": "sha2.message-schedule-step@1",
      "params": {}
    }
  ]
}
\`\`\`

Parent-scope state must be the 64-byte padded block (16 seed words). After
48 iterations, the FES-with-history exits with parent-scope state =
\`W_0..W_63\` concatenated (256 bytes).

## Why a SHA-256-specific helper

Slice 2.6b re-scope discovery (2026-05-25): expressing this recurrence as
a port-native composition of \`rotate-bits-right\` + \`shift-bits-right\` +
\`xor\` + \`add-mod-32\` requires bridge primitives that don't yet exist
(aux-key → port input). Ships at coarser granularity now; Slice 2.6d
decomposes once the bridge vocabulary lands. The math is identical to
the future composition — pinned at test scope in
\`tests/sha256-message-schedule.test.ts\` (Slice 2.5).

## Errors

- Throws if any of \`aux["prior-2"]\`, \`aux["prior-7"]\`,
  \`aux["prior-15"]\`, \`aux["prior-16"]\` is missing or wrong-shape.
  Loud failure is intentional — the FES-with-history runtime should
  always set these.

## Phase status

Shipped in Slice 2.6b of the universal-port-dataflow plan. Subject to
decomposition into port-native primitives in Slice 2.6d once the bridge
vocabulary (aux-to-port) is designed in 2.6c.`,
  params: new Map([["(no params)", "This step takes no parameters; pass `{}`."]]),
  references: [
    "FIPS 180-4 §6.2.2 step 1 (SHA-256 message schedule expansion)",
    "FIPS 180-4 §4.1.2 (σ0, σ1 helper definitions)",
    "docs/plans/universal-port-phase-2-slices.md (Slice 2.6b)",
  ],
  shapeContract: { input: "bytes", output: "bytes" },
};

// ─── Universal port-dataflow metadata ─────────────────────────────────────
//
// Lifted-legacy registration. The body's parent-scope state (per
// FES-with-history's contract) is reset to a 4-byte zero buffer at the
// start of each iteration, so the legacy executor's `state` argument
// arrives as a 4-byte BytesState that we ignore (the recurrence inputs
// come entirely from aux). The output state is the computed W_t (4 bytes).
// `meta.stateInputPort` + `stateOutputPort` carry these through.
//
// `meta.auxReadPorts`: the four lookback aux keys mapped to four named
// input ports. Names match the aux keys for symmetry — the runtime aliases
// the live aux values into the synthetic `ctx.aux` via the auxKey side of
// the binding, while the port-input names are the SAME strings (so a
// future port-edge wired spec can refer to either by the same name).

export const sha2MessageScheduleStepMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
  auxReadPorts: (_params: Json): ReadonlyMap<string, string> =>
    new Map([
      ["prior-2", "prior-2"],
      ["prior-7", "prior-7"],
      ["prior-15", "prior-15"],
      ["prior-16", "prior-16"],
    ]),
};

/**
 * Declared port surface. State ports byteLength=4 (fixed by the
 * historyEntryByteLength=4 of the FES-with-history node that wraps this
 * leaf). Four aux input ports for the priors, also byteLength=4.
 *
 * Note on the executor↔contract relationship: the executor's `_state`
 * argument is unused (the FES-with-history walker resets it to zero
 * bytes anyway). The contract declares `state` as byteLength=4 to match
 * what the runtime projects, satisfying the port-coercion check without
 * spurious truncation/zero-pad frames.
 */
export const sha2MessageScheduleStepPortContract: PortContract = {
  inputs: new Map<string, PortShape>([
    ["state", { byteLength: 4, layout: "raw" }],
    ["prior-2", { byteLength: 4, layout: "raw" }],
    ["prior-7", { byteLength: 4, layout: "raw" }],
    ["prior-15", { byteLength: 4, layout: "raw" }],
    ["prior-16", { byteLength: 4, layout: "raw" }],
  ]),
  outputs: new Map<string, PortShape>([["state", { byteLength: 4, layout: "raw" }]]),
};
