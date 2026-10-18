/**
 * ml-dsa.attempt-verdict — keep this candidate signature, or throw it away?
 * The rejection test at the heart of ML-DSA signing (FIPS 204 Algorithm 7,
 * lines 23–28). `docs/plans/refactored-petting-tide.md`, P4.
 *
 * ## Four checks, one decision
 *
 * Every attempt produces a candidate `(c̃, z, h)`. It is published only if all
 * four of these hold — each measured by its own visible step upstream:
 *
 * - **‖z‖∞ < γ1 − β** (`zq-inf-norm-below@1`) — z = y + c·s1 must not reveal
 *   s1. Within this bound, z is distributed the same whatever s1 is.
 * - **‖r0‖∞ < γ2 − β** (`zq-inf-norm-below@1`) — subtracting c·s2 must not
 *   change w's high bits, or the verifier would rebuild a different w1.
 * - **‖c·t0‖∞ < γ2** (`zq-inf-norm-below@1`) — the dropped low part of the
 *   public key must be small enough for the hint to repair.
 * - **#h ≤ ω** (`ml-dsa.hint-count@1`) — the hint must fit its fixed-size slot.
 *
 * ## Three ports per check: the flag decides, the other two are for reading
 *
 * Each check arrives as a flag (`zOk`), the measured value (`zNorm`) and the
 * limit it was held to (`zBound`). **Only the flags decide** — the comparison
 * rule (strict `<` for norms, `≤` for the hint count) lives in the check steps
 * and nowhere else, so this step cannot disagree with them about an edge case.
 * The value and limit ports are display ports, the `twofish.h-expand@1`
 * precedent: they exist so the narrator can say "‖z‖∞ = 131,029 ≥ 130,994"
 * (attempt 1 of the default pair) rather than "z failed", because a narrator
 * sees only its own frame.
 *
 * ## Two outputs
 *
 * - `accepted` — one byte, 1 if every check passed. The attempt loop's
 *   `stopWhen` reads it, and the candidate is multiplied by it before packing
 *   (a rejected candidate becomes zeros, so the strict packers never see a z
 *   out of range or a hint over ω).
 * - `failed` — one byte recording WHICH checks failed (bit 0 z, bit 1 r0,
 *   bit 2 ct0, bit 3 hint). It is the loop's per-attempt output, so the loop
 *   leaves behind a one-byte-per-attempt log of why each attempt was rejected.
 *
 * ## Every check runs on every attempt
 *
 * FIPS stops at the first failure. A spec is straight-line, so here all four are
 * always computed — which is why the log can record more than one failure for
 * one attempt, and why `failed` is a set, not a single reason.
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. No params.
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

const STEP = "ml-dsa.attempt-verdict";

/** The four checks, in FIPS 204's order, with their bit in `failed`. */
export const ATTEMPT_CHECKS = [
  { name: "z", bit: 1 },
  { name: "r0", bit: 2 },
  { name: "ct0", bit: 4 },
  { name: "hint", bit: 8 },
] as const;

export type AttemptCheck = (typeof ATTEMPT_CHECKS)[number]["name"];

/** Port names for one check: its flag, its measured value, its limit. */
export const attemptCheckPorts = (
  check: AttemptCheck,
): { readonly ok: string; readonly value: string; readonly limit: string } =>
  check === "hint"
    ? { ok: "hintOk", value: "hintCount", limit: "omega" }
    : { ok: `${check}Ok`, value: `${check}Norm`, limit: `${check}Bound` };

/** Decode a `failed` byte into the names of the checks it records. */
export const failedChecks = (failed: number): AttemptCheck[] =>
  ATTEMPT_CHECKS.filter((c) => (failed & c.bit) !== 0).map((c) => c.name);

export const mlDsaAttemptVerdictPortContract: PortContract = {
  inputs: new Map(
    ATTEMPT_CHECKS.flatMap(({ name }) => {
      const p = attemptCheckPorts(name);
      return [
        [p.ok, { layout: "raw" as const, byteLength: 1 }],
        [p.value, { layout: "raw" as const }],
        [p.limit, { layout: "raw" as const }],
      ] as const;
    }),
  ),
  outputs: new Map([
    ["accepted", { layout: "raw", byteLength: 1 }],
    ["failed", { layout: "raw", byteLength: 1 }],
  ]),
};

/** A one-byte 0/1 flag port, read strictly: anything else is a wiring mistake. */
const readFlag = (inputs: ReadonlyMap<string, Uint8Array>, name: string): boolean => {
  const bytes = inputs.get(name);
  if (bytes === undefined) throw new Error(`${STEP}: missing required input port "${name}"`);
  if (bytes.length !== 1 || (bytes[0] !== 0 && bytes[0] !== 1)) {
    throw new Error(`${STEP}: "${name}" must be a one-byte flag, 0 or 1`);
  }
  return bytes[0] === 1;
};

export const mlDsaAttemptVerdict: PortedExecutor = (inputs, _params, _ctx) => {
  let failed = 0;
  for (const { name, bit } of ATTEMPT_CHECKS) {
    const ports = attemptCheckPorts(name);
    if (!readFlag(inputs, ports.ok)) failed |= bit;
    // The display ports must be wired even though they do not decide: a
    // verdict that cannot say what it measured is the thing this step exists
    // to prevent.
    for (const display of [ports.value, ports.limit]) {
      if (inputs.get(display) === undefined) {
        throw new Error(`${STEP}: missing required input port "${display}"`);
      }
    }
  }
  return new Map([
    ["accepted", new Uint8Array([failed === 0 ? 1 : 0])],
    ["failed", new Uint8Array([failed])],
  ]);
};

export const mlDsaAttemptVerdictDoc: StepDocumentation = {
  name: "Keep or reject this attempt (ML-DSA)",
  summary:
    "Combines signing's four safety checks: the candidate signature is kept only if every one passes.",
  detail: `# Keep or reject this attempt

Signing makes a **candidate** signature and then asks four questions about it.
The candidate is published only if the answer to all four is yes; otherwise it
is thrown away and the signer tries again with a fresh mask.

- **Is every coefficient of z below γ1 − β?** z = y + c·s1 contains the secret
  s1. Inside this bound, every possible s1 produces z values that look the same,
  so z gives nothing away. A candidate outside it could.
- **Is every coefficient of r0 below γ2 − β?** The verifier must arrive at the
  same rounded commitment w1 as the signer. If subtracting c·s2 pushed a value
  across a rounding boundary, it would not.
- **Is every coefficient of c·t0 below γ2?** The public key drops the low bits
  t0. The hint can repair that loss only if c·t0 is small.
- **Does the hint have at most ω ones?** The signature has a fixed number of
  slots for hint positions.

The first two fail often (each attempt has roughly a one-in-four chance of
passing everything, so a signature takes about four attempts). The hint count
fails rarely, and c·t0 practically never with a genuine key.

**This step does not measure anything itself.** Each check is its own step just
before this one; this step reads their answers, and also the measured values
and limits so it can say exactly why an attempt failed.

**Outputs:** \`accepted\` (1 if all four pass) and \`failed\`, one byte recording
which checks failed: 1 = z, 2 = r0, 4 = c·t0, 8 = hint. Every check is computed on
every attempt, so one attempt can fail more than one.`,
  params: new Map(),
  references: ["FIPS 204 Algorithm 7 (ML-DSA.Sign_internal), lines 23–28", "FIPS 204 §6.2"],
};
