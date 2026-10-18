/**
 * ml-dsa.verdict — the last line of ML-DSA verification (FIPS 204 Algorithm 8,
 * step 13): accept the signature, or do not.
 *
 * Four input ports and one output:
 *
 * - `challenge` — c̃, the 32-byte challenge seed carried IN the signature;
 * - `recomputed` — c̃′, the verifier's own hash of μ ‖ w1Encode(w1′);
 * - `normOk` — one byte, 1 if ‖z‖∞ < γ1 − β (from `zq-inf-norm-below@1`);
 * - `hintValid` — one byte, 1 if the packed hint was well formed (from
 *   `ml-dsa.hint-unpack@1`'s `valid` port);
 * - `output` — one byte, 1 (valid) or 0 (invalid).
 *
 * ## Three conditions, and each one guards a different door
 *
 * FIPS writes the return value as `[[ ‖z‖∞ < γ1 − β ]] and [[ c̃ = c̃′ ]]`, with
 * the malformed-hint case returning false earlier, at HintBitUnpack. Here all
 * three meet in one place, so the trace has a single frame that says which of
 * them a rejected signature broke:
 *
 * 1. **c̃ = c̃′** is the signature equation. The verifier rebuilds the signer's
 *    commitment w1 from public data alone, hashes it, and gets the signer's
 *    challenge back only if the signer knew the secret key.
 * 2. **‖z‖∞ < γ1 − β** is what keeps z from leaking the key. A forger with no
 *    key could satisfy the equation with a huge z; the bound is what makes that
 *    impossible.
 * 3. **The hint is well formed**: there is exactly one way to write a given
 *    hint, so a valid signature cannot be rewritten into a second valid one.
 *
 * ## Why every input is always present
 *
 * A spec is straight-line, so verification never returns early: a malformed
 * hint still reaches this step, as the all-zero hint `hint-unpack@1` emits with
 * `valid = 0`. That is the honest depiction — the flag, not control flow,
 * carries the refusal — and it means the other two conditions are computed and
 * visible even for a signature already doomed by its hint.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. No params — every
 * fact it needs is wired.
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

const STEP = "ml-dsa.verdict";

export const mlDsaVerdictPortContract: PortContract = {
  inputs: new Map([
    ["challenge", { layout: "raw" }],
    ["recomputed", { layout: "raw" }],
    ["normOk", { layout: "raw", byteLength: 1 }],
    ["hintValid", { layout: "raw", byteLength: 1 }],
  ]),
  outputs: new Map([["output", { layout: "raw", byteLength: 1 }]]),
};

/** A one-byte 0/1 flag port, read strictly: anything else is a wiring mistake. */
const readFlag = (inputs: ReadonlyMap<string, Uint8Array>, name: string): boolean => {
  const bytes = inputs.get(name);
  if (bytes === undefined) throw new Error(`${STEP}: missing required input port "${name}"`);
  if (bytes.length !== 1 || (bytes[0] !== 0 && bytes[0] !== 1)) {
    throw new Error(
      `${STEP}: "${name}" must be a one-byte flag, 0 or 1 (got ${bytes.length} byte(s))`,
    );
  }
  return bytes[0] === 1;
};

/**
 * Do the two challenge seeds agree? Compared without an early exit, the way a
 * real verifier is written — not because verification handles a secret (it
 * does not), but so the habit is the same one the signer needs.
 */
export const challengesMatch = (a: Uint8Array, b: Uint8Array): boolean => {
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
};

export const mlDsaVerdict: PortedExecutor = (inputs, _params, _ctx) => {
  const challenge = inputs.get("challenge");
  const recomputed = inputs.get("recomputed");
  if (challenge === undefined) throw new Error(`${STEP}: missing required input port "challenge"`);
  if (recomputed === undefined) {
    throw new Error(`${STEP}: missing required input port "recomputed"`);
  }
  if (challenge.length !== recomputed.length) {
    throw new Error(
      `${STEP}: "challenge" is ${challenge.length} bytes but "recomputed" is ${recomputed.length}; both are c̃, so they must be the same width`,
    );
  }
  const normOk = readFlag(inputs, "normOk");
  const hintValid = readFlag(inputs, "hintValid");
  const valid = hintValid && normOk && challengesMatch(challenge, recomputed);
  return new Map([["output", new Uint8Array([valid ? 1 : 0])]]);
};

export const mlDsaVerdictDoc: StepDocumentation = {
  name: "Verdict — accept or reject the signature",
  summary:
    "Valid only if the recomputed challenge matches the one in the signature, z is small enough, and the hint was well formed.",
  detail: `# Verdict

The last step of verification. The signature is **valid** (1) only if all three
hold, and **invalid** (0) otherwise:

\`\`\`
valid = hint well formed  and  ‖z‖∞ < γ1 − β  and  c̃ = c̃′
\`\`\`

## The challenge comparison is the signature equation

The signer hashed its commitment w1 into a challenge c̃ and put c̃ in the
signature. The verifier never sees w1. It rebuilds it from the public key, the
signature's z and its hint, hashes that, and gets c̃′. The two agree only if
the signature was made with the secret key that matches this public key, for
this exact message.

## The norm check is what stops a forger

Without the bound on z, the equation alone could be satisfied by someone with
no key at all, using a large enough z. Keeping every coefficient of z below
γ1 − β is what makes that impossible. It is also why the signer throws away
candidates: a z that came out too large would reveal information about the
secret.

## The hint check stops a second signature

A hint can be written down in only one way. A signature whose hint bytes break
the format is refused, so nobody holding one valid signature can rewrite its
hint into a different, also-valid one.

## No early exit

All three inputs are computed for every signature, even one whose hint was
already refused. The refusal travels as a flag, which is why this one step can
say which check a rejected signature failed.`,
  params: new Map(),
  references: [
    "FIPS 204 Algorithm 8 (ML-DSA.Verify_internal) — step 13, the return value",
    "FIPS 204 Algorithm 21 (HintBitUnpack) — the malformed-hint refusal",
  ],
};
