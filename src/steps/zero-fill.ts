/**
 * Zero-fill — port-native emitter of `byteLength` zero bytes
 * (PRNG family, `docs/plans/iterative-dancing-ocean.md` Phase P1).
 *
 * Zero input ports. One output port `output` carrying exactly
 * `params.byteLength` zero bytes. That is the whole executor — the interesting
 * part is entirely about WHY a step whose output is always zeros earns a place
 * in a trace.
 *
 * **This is the request for randomness, and its width is what drives the loop.**
 * A pseudo-random generator has no message input. Nothing about a seed says how
 * many bytes you want out of the generator; that is a separate question the user
 * asks. The port-mode `iterate` (`core/runtime.ts`) derives its iteration count
 * from `seedInput.length / blockByteLength`, so *something* has to carry the
 * requested length into the spec as bytes. This leaf is that something: bind it
 * to an iterate's `seedInput` at width N and the generator runs `ceil(N / w)`
 * times, each iteration handed a `w`-wide slice it is free to ignore.
 *
 * The zeros themselves are never read. What is read is how many there are.
 *
 * **Why not `constant-load@1` with an N-element zero array.** It would work, and
 * it would cost no new step type. Two reasons it is the wrong call here. First,
 * `constant-load@1` documents itself as the emitter of *published cryptographic
 * constants* — round constants, IVs, S-box tables. Pressing it into service as a
 * length-carrier makes the trace say "here is a 256-byte published constant" to
 * a learner reading it, which is a category lie in an app whose entire value is
 * that the trace tells the truth. Second, its bytes are literal spec data, so
 * every saved and URL-shared PRNG document would carry a several-hundred-element
 * array of zeros whose only meaningful content is its `.length`.
 *
 * **Why the last block being short is free.** The iterate's
 * `allowPartialFinalBlock` relaxes the block-multiple requirement to `ceil` and
 * hands the final iteration a short `in` block. A generator body pairs that with
 * `truncate-to-reference@1` to trim its output word to the same width — the
 * mechanism CTR / CFB / OFB / ChaCha20 / Salsa20 already use for a ragged tail.
 * So a request for 41 bytes from a 4-byte generator yields exactly 41 bytes: ten
 * whole words and one trimmed to a single byte.
 *
 * **Authoring conventions.** Port-native bare name: `kind: "ported"`, no
 * `legacy`, no `meta`, no `shapeContract` — the same posture as
 * `constant-load.ts`, whose function-form output contract this mirrors (the
 * output byteLength is a function of params, so it can be declared honestly to
 * the editor at spec time).
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  StepDocumentation,
} from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly byteLength: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("zero-fill: params must be an object");
  }
  const p = params as Record<string, Json>;
  const byteLength = p.byteLength;
  // Zero is rejected as well as negatives: a zero-width request would give the
  // iterate a count of 0, so the body would never run and `bodyOutput` would
  // never resolve. Failing here names the real problem instead of surfacing it
  // as a confusing empty-output trace.
  if (typeof byteLength !== "number" || !Number.isInteger(byteLength) || byteLength < 1) {
    throw new Error(
      `zero-fill: params.byteLength must be a positive integer (got ${String(byteLength)})`,
    );
  }
  return { byteLength };
};

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Empty input map (this is an emitter). Function-form output because the output
 * port's `byteLength` is a function of `params.byteLength` — the same shape
 * `constant-load@1` uses, and for the same reason: declaring the exact width at
 * spec time lets the editor's coercion-warning glyphs be precise.
 */
export const zeroFillPortContract: PortContract = {
  inputs: new Map(),
  outputs: (params: Json) => {
    const { byteLength } = readParams(params);
    const shape: PortShape = { layout: "raw", byteLength };
    return new Map([["output", shape]]);
  },
};

export const zeroFill: PortedExecutor = (_inputs, params, _ctx) => {
  const { byteLength } = readParams(params);
  // `Uint8Array` is zero-initialized by construction; a fresh one per call so
  // downstream mutation cannot leak between iterations.
  return new Map([["output", new Uint8Array(byteLength)]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const zeroFillDoc: StepDocumentation = {
  name: "Request output",
  summary:
    "Reserves the space for the bytes you asked for. Its width is what tells a generator how many times to run.",
  detail: `# Request output

Produces a run of zero bytes, as many as you ask for in \`byteLength\`. The
zeros are not the point — **the length is**.

## Why a step that only makes zeros

A cipher knows how much work to do because it is handed a message: encrypting
100 bytes means processing 100 bytes. A **pseudo-random generator has no
message**. You give it a seed, which says *which* sequence to produce, but
nothing in the seed says *how much* of that sequence you want. That is a
separate question, and this step is where the answer enters the cipher.

Wire it into a loop's input and the loop runs once for every whole block that
fits, plus one more for any remainder:

\`\`\`
blocks = ceil(byteLength / block width)
\`\`\`

Ask a 4-byte generator for 41 bytes and it runs 11 times — ten full words and
one final word trimmed to a single byte.

## Reading a trace

Each pass through the loop is handed its own slice of this buffer. A generator
**ignores** that slice completely: it builds its next value from its own
internal state, not from anything you fed in. Watching those zeros arrive and
go unused is a fair picture of what a generator is — a machine that makes
output from nothing but its own state and the rule it follows.

The final short slice is the exception, and it *is* read: a generator matches
its last output to that width so you get back exactly the number of bytes you
requested, with nothing padded and nothing spare.`,
  params: new Map([
    [
      "byteLength",
      "How many bytes to produce — a positive whole number. This is the amount of output you are asking the generator for, and it sets how many times the generator runs.",
    ],
  ]),
  references: [],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract.
};
