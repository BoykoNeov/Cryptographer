/**
 * ml-dsa.release-signature — the last step of ML-DSA signing: hand out the
 * signature, or say plainly that there is none. `docs/plans/refactored-petting-tide.md`, P4.
 *
 * ## Why signing needs a final step at all
 *
 * The attempt loop stops at the first accepted candidate — or at its cap, the
 * most attempts it is allowed (FIPS 204 §3.4 permits an implementation to bound
 * the loop). A capped loop that never accepted still leaves a candidate on its
 * chain: rejected attempts are multiplied by zero before packing, so that
 * candidate is 2,420 well-formed bytes of an all-zero z and hint. Emitting those
 * as "the signature" would hand a learner something that looks real and that
 * they might paste into verification. So this step looks at the accept flag the
 * loop carried out:
 *
 * - accepted ⇒ `output` is the signature, unchanged;
 * - never accepted ⇒ `output` is EMPTY, and the narrator says why.
 *
 * ## Three inputs
 *
 * - `accepted` — one byte, from the loop's harvested chain;
 * - `signature` — the candidate on the chain when the loop stopped;
 * - `log` — the loop's per-attempt output: one `failed` byte per attempt
 *   (`ml-dsa.attempt-verdict@1`). Its LENGTH is how many attempts ran, and its
 *   bytes say what rejected each one. Only the narrator reads it.
 *
 * This is a select, not a branch, in the same sense as ML-KEM's
 * `ml-kem.select-shared-secret@1`: the spec does not fork, it picks one of two
 * values. Unlike decapsulation, nothing here is secret — a signer that gave up
 * may say so — so the output may differ in length.
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. No params.
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

const STEP = "ml-dsa.release-signature";

export const mlDsaReleaseSignaturePortContract: PortContract = {
  inputs: new Map([
    ["accepted", { layout: "raw", byteLength: 1 }],
    ["signature", { layout: "raw" }],
    ["log", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const mlDsaReleaseSignature: PortedExecutor = (inputs, _params, _ctx) => {
  const accepted = inputs.get("accepted");
  const signature = inputs.get("signature");
  const log = inputs.get("log");
  if (accepted === undefined) throw new Error(`${STEP}: missing required input port "accepted"`);
  if (signature === undefined) throw new Error(`${STEP}: missing required input port "signature"`);
  if (log === undefined) throw new Error(`${STEP}: missing required input port "log"`);
  if (accepted.length !== 1 || (accepted[0] !== 0 && accepted[0] !== 1)) {
    throw new Error(`${STEP}: "accepted" must be a one-byte flag, 0 or 1`);
  }
  return new Map([["output", accepted[0] === 1 ? new Uint8Array(signature) : new Uint8Array(0)]]);
};

export const mlDsaReleaseSignatureDoc: StepDocumentation = {
  name: "Release the signature (ML-DSA)",
  summary:
    "Outputs the signature if an attempt was accepted, or nothing if the signer gave up at its attempt limit.",
  detail: `# Release the signature

The last step of signing. The attempt loop ended for one of two reasons:

- **An attempt passed all four checks.** Its candidate is the signature, and
  this step outputs it unchanged.
- **The loop reached its limit without accepting anything.** There is no
  signature. This step outputs nothing at all, rather than the all-zero
  candidate the last rejected attempt left behind, which would look like a real
  signature and verify as invalid.

With the standard parameters an attempt is accepted about one time in four, so
running out of attempts is very unlikely — unless the bounds have been edited
tighter, which is exactly the experiment the limit makes safe to run.`,
  params: new Map(),
  references: ["FIPS 204 Algorithm 7 (ML-DSA.Sign_internal)", "FIPS 204 §3.4"],
};
