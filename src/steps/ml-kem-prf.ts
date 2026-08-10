/**
 * ml-kem.prf — ML-KEM's `PRF_η`, which is SHAKE256 squeezed to `64η` bytes
 * (FIPS 203 §4.1).
 *
 * One input port `input` carrying `σ ‖ N` — the 32-byte noise seed followed by a
 * one-byte counter — and one output port `output` carrying `64η` bytes of
 * uniform randomness, which `zq-cbd@1` then turns into a noise polynomial.
 *
 * ## The counter byte is concatenated OUTSIDE this step, on purpose
 *
 * It would be less wiring to take `N` as a param. The counter is the reason six
 * different polynomials come out of one 32-byte seed, and getting its order
 * wrong — sampling `e` on 0,1,2 and `s` on 3,4,5 — produces a key pair that is
 * perfectly self-consistent and matches no other implementation. That is a
 * fact about the ALGORITHM, so it belongs on the canvas as a visible
 * `constant-load@1` feeding a visible `concat@1`, not buried in a params blob.
 *
 * ## Why the output length is `64η` and not a free parameter
 *
 * The consumer is a centred-binomial sampler that spends `2η` bits per
 * coefficient over 256 coefficients: `256 · 2η` bits = `64η` bytes, exactly.
 * The sizes line up by design, so deriving the length from `η` here means a
 * learner who edits `η` gets a spec that still runs instead of one that throws
 * a length mismatch two steps later.
 *
 * ## Why `PRF` rather than "SHAKE256 again"
 *
 * Because of what it is used for. `H` and `G` hash values that are already
 * committed; this one *stretches a secret*. Its input is 32 secret bytes and its
 * output is hundreds of bytes that must be indistinguishable from random to
 * anyone who does not have them. FIPS 203 gives it its own name for that reason
 * and so does this step type.
 *
 * See `ml-kem-hash-g.ts` for the cross-reference-monolith note covering this
 * family.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import { shake256 } from "../ciphers/keccak-compute";
import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";

const STEP = "ml-kem.prf";

/** FIPS 203 §4.1: `PRF_η(s, b) = SHAKE256(s ‖ b, 64η)`. */
const BYTES_PER_ETA = 64;

/** ML-KEM's parameter sets use η ∈ {2, 3}; the sampler needs at least 1. */
const readEta = (params: Json): number => {
  const eta = (params as Record<string, unknown>).eta;
  if (typeof eta !== "number" || !Number.isInteger(eta) || eta < 1 || eta > 8) {
    throw new Error(`${STEP}: params.eta must be an integer in 1…8 (ML-KEM uses 2 or 3)`);
  }
  return eta;
};

export const mlKemPrfPortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: (params: Json) =>
    new Map([["output", { layout: "raw" as const, byteLength: BYTES_PER_ETA * readEta(params) }]]),
};

export const mlKemPrf: PortedExecutor = (inputs, params, _ctx) => {
  const eta = readEta(params);
  const input = inputs.get("input");
  if (input === undefined) {
    throw new Error(`${STEP}: requires an "input" port carrying σ ‖ N`);
  }
  return new Map([["output", shake256(input, BYTES_PER_ETA * eta)]]);
};

export const mlKemPrfDoc: StepDocumentation = {
  name: "PRF — stretch the noise seed (SHAKE256)",
  summary:
    "SHAKE256 over the 32-byte secret seed plus a one-byte counter, squeezed to 64η bytes — enough randomness for exactly one noise polynomial.",
  detail: `# PRF — stretch the noise seed

Takes 33 bytes — the secret seed \`σ\` followed by a one-byte counter — and
squeezes **SHAKE256** for \`64η\` bytes of output.

## One seed, six polynomials

Key generation needs six noise polynomials: three for the secret \`s\` and three
for the error \`e\`. All six come out of the same 32 secret bytes. The only thing
that distinguishes them is that counter byte, which runs

\`\`\`
0, 1, 2   →  s₀, s₁, s₂
3, 4, 5   →  e₀, e₁, e₂
\`\`\`

You can see it being attached, just above this step: a one-byte constant and a
join. It is deliberately not hidden in this step's settings, because the order
matters and it is exactly the sort of thing that goes wrong invisibly. Swap the
two groups — sample \`e\` first — and you get a key pair that is entirely
self-consistent, passes every round-trip test you could write, and cannot
interoperate with a single other implementation on earth.

## Why exactly 64η bytes

The next step spends \`2η\` bits per coefficient and needs 256 coefficients:

\`\`\`
256 coefficients × 2η bits = 512η bits = 64η bytes
\`\`\`

So the length is not a free choice, it is what the consumer eats. That is why it
is derived from η here rather than set separately — change η and the amount of
randomness follows.

## Why this is a PRF and not "another hash"

\`H\` and \`G\` hash things that are already fixed. This one takes a small secret
and stretches it into a lot of output that has to be indistinguishable from
random to anyone who does not hold the secret. Same sponge, different job — and
the specification names it separately for that reason.

The sponge itself is the one under **Hash → SHAKE256** in the algorithm
selector, opened out into 216 frames.`,
  params: new Map([
    [
      "eta",
      "Half the coin flips per noise coefficient, and the sole determinant of how much randomness is squeezed: 64η bytes. ML-KEM-768 uses η = 2 everywhere. The value must match the sampler consuming this output.",
    ],
  ]),
  references: [
    "FIPS 203 §4.1 — PRF_η(s, b) = SHAKE256(s ‖ b, 64η)",
    "FIPS 203 Algorithm 13 — K-PKE.KeyGen, where the counter runs 0…2 for s and 3…5 for e",
    "FIPS 202 §6.2 — SHAKE256",
  ],
};
